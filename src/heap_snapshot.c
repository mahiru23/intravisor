#include "monitor.h"
#include "uthash/uthash.h"
#include "uthash/utarray.h"

// we need socket list & output buffer (UDP?)
// maybe written in socket_list.c, not here

// ...........
// save heap to resume program with malloc/...
// very similar to stack, reuse most code, change existed implementation


// we use uthash to save heap page
struct page {
    void *addr; // primary key for hash
    char content[PAGE_SIZE];
    char cap_tags[PAGE_SIZE/16]; // PAGE_SIZE / cap_size
    UT_hash_handle hh;
};

struct page *heap = NULL;
//struct page *stack = NULL;
static char *heap_dirty_page_map = NULL;
static char *heap_dirty_page_map_temp = NULL; // TODO: change syscall, we should not use it, and same in stack
static int heap_page_num;
static void *heap_addr;
static bool heap_cap_tags[256]; // 1 page

char *heap_dirty_page_packet;
int global_heap_dirty_page_num;

void heap_page_init(int cid) {

    printf("heap_page_init\n");

    heap_addr = cvms[cid].heap;
    heap_page_num = cvms[cid].heap_size/PAGE_SIZE;
    heap_dirty_page_map = (char *)malloc(heap_page_num);
    if (heap_dirty_page_map == NULL) {
        perror("malloc heap_dirty_page_map error");
        exit(EXIT_FAILURE);
    }
    heap_dirty_page_map_temp = (char *)malloc(heap_page_num);
    if (heap_dirty_page_map_temp == NULL) {
        perror("malloc heap_dirty_page_map_temp error");
        exit(EXIT_FAILURE);
    }
}

void heap_dir_init() {

    printf("heap_dir_init\n");

    if(mkdir("snapshot", S_IRWXU) != 0) {
        if(errno != EEXIST) {
            perror("mkdir snapshot");
            exit(EXIT_FAILURE);
        }
        else {
            if (system("rm -rf snapshot") == -1) {
                perror("rm -rf snapshot");
                exit(EXIT_FAILURE);
            }
            if(mkdir("snapshot", S_IRWXU) != 0) {
                if(errno != EEXIST) {
                    perror("mkdir snapshot");
                    exit(EXIT_FAILURE);
                }
            }
        }
    }
}

static struct page * heap_page_add_update(void *addr, const char *cap_tags) {
    struct page *s;
    HASH_FIND_PTR(heap, &addr, s);

    if (s == NULL) {
        s = (struct heap *)malloc(sizeof(struct page));
        if (s == NULL) {
            perror("heap_page_add_update: malloc struct page error");
            exit(EXIT_FAILURE);
        }
        s->addr = addr;
        HASH_ADD_PTR(heap, addr, s);
    }
    memcpy(s->content, addr, PAGE_SIZE);
    memcpy(s->cap_tags, cap_tags, sizeof(s->cap_tags));
    return s;
}



static int heap_get_cap_info(void *addr, size_t size) {
    uintcap_t *stack_ptr = (uintcap_t *)(addr);
    int elem_len = sizeof(uintcap_t *) * 2;
    memset(heap_cap_tags, 0, sizeof(heap_cap_tags));
    int sum_cap = 0;
    for (size_t i = 0; i < size / elem_len; ++i) {
        if (is_capability(stack_ptr[i])) {
            if(cheri_getperm(stack_ptr[i]) == 0) {
                int tag = is_capability(stack_ptr[i]);
                printf("tag: %d\n", tag);
                printf("[capture]: heap_get_cap_info: perm = 0 !\n");
                CHERI_CAP_PRINT(stack_ptr[i]);
            }
            //int no = (addr - heap_addr) / PAGE_SIZE;
            heap_cap_tags[i] = 1;
            sum_cap++;
        }
    }
    return sum_cap;
}

// create file for each page, save struct page
static void write_to_heapfile(struct page *s, int page_no) {
    char pathname[40];
    snprintf(pathname, sizeof(pathname), "snapshot/heap_%d", page_no);
    int fd = open(pathname, O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    if (write(fd, s, sizeof(struct page)) == -1) {
        perror("write_to_heapfile write");
        close(fd);
        exit(EXIT_FAILURE);
    }
    close(fd);
}

static void read_from_heapfile(struct page *s, const char* pathname) {
    int fd = open(pathname, O_RDONLY);
    if (fd == -1) {
        perror("read_from_heapfile open");
        exit(EXIT_FAILURE);
    }
    if (read(fd, s, sizeof(struct page)) == -1) {
        perror("read_from_heapfile read");
        close(fd);
        exit(EXIT_FAILURE);
    }
    close(fd);
}



// general function for heap/stack/other memory segment
static int memory_page_update(void *addr, unsigned long size, char *dirty_page_map, char *dirty_page_map_temp) {
    int dirty_page_num = 0;
    int page_num = size / PAGE_SIZE;
    memset(dirty_page_map, 0, sizeof(dirty_page_map));

#if DEBUG
    printf("addr: %p, size: 0x%lx, dirty_page_map: %p, dirty_page_map_temp: %p, heap_page_num: %d\n", \
    addr, size, dirty_page_map, dirty_page_map_temp, heap_page_num);
#endif

    if (mincore(addr, size, dirty_page_map) == -1) {
        perror("mincore");
        exit(EXIT_FAILURE);
    }

    global_heap_dirty_page_num = get_dirty_page_num(size, page_num, addr);
    heap_dirty_page_packet = (char *)malloc(global_heap_dirty_page_num*PAGE_SIZE);
    if (heap_dirty_page_packet == NULL) {
        perror("malloc heap_dirty_page_packet error");
        exit(EXIT_FAILURE);
    }

#if DEBUG
    printf("heap_dirty_page_packet size: %d\n", global_heap_dirty_page_num*PAGE_SIZE);
#endif

    for (int i = 0; i < page_num; i++) {
        if (dirty_page_map[i] & MINCORE_MODIFIED) {
            heap_get_cap_info(addr+i*PAGE_SIZE, PAGE_SIZE);
            struct page *s = heap_page_add_update(addr+i*PAGE_SIZE, heap_cap_tags);
            write_to_heapfile(s, i);
            memcpy((void *)(heap_dirty_page_packet + dirty_page_num*PAGE_SIZE), s, sizeof(struct page));
            dirty_page_num++;
        }
    }
#if DEBUG
    printf("heap before msync_manual: %d\n", dirty_page_num);
#endif
    if (msync_manual(addr, size, dirty_page_map_temp) == -1) {
        perror("msync_manual heap");
        exit(EXIT_FAILURE);
    }
#if DEBUG
    printf("heap after msync_manual: ");
    get_dirty_page_num(size, page_num, addr);
#endif
    return dirty_page_num;
}

// api for master
void heap_dirty_page_snapshot(void *addr, unsigned long size) {
    memory_page_update(addr, size, heap_dirty_page_map, heap_dirty_page_map_temp);
}

// for backup
void save_heap_dirty_page_to_disk(void *addr, unsigned long size) {
    int packet_page_num = size / PAGE_SIZE;
    for(int i=0; i<packet_page_num; i++) {
        struct page *s = (struct heap *)malloc(sizeof(struct page));
        if(s == NULL) {
            perror("save_heap_dirty_page_to_disk: malloc struct page error");
            exit(EXIT_FAILURE);
        }
        memcpy(s, addr+i*PAGE_SIZE, PAGE_SIZE);
        int page_no = (s->addr - heap_addr) / PAGE_SIZE;
        write_to_heapfile(s, page_no);
    }
}

// for backup
void save_heap_dirty_page_to_memory(void *addr, unsigned long size) {
    int packet_page_num = size / PAGE_SIZE;
    for(int i=0; i<packet_page_num; i++) {
        struct page *s = (struct heap *)malloc(sizeof(struct page));
        if(s == NULL) {
            perror("save_heap_dirty_page_to_disk: malloc struct page error");
            exit(EXIT_FAILURE);
        }
        memcpy(s, addr+i*PAGE_SIZE, PAGE_SIZE);
        struct page *s_temp;
        void *key = s->addr;
        HASH_FIND_PTR(heap, &key, s_temp);
        if (s_temp == NULL) {
            HASH_ADD_PTR(heap, addr, s);
        } 
        else {
            memcpy(s_temp, addr+i*PAGE_SIZE, PAGE_SIZE);
        }
        free(s);
    }
}

void set_cap_tags_map_info(void *addr, char *cap_tags_map, char *cap_tags_length) {
    uintcap_t *heap_ptr = (uintcap_t *)(addr);
    uintcap_t *ptr = (uintcap_t *)(addr);
    for (int i=0; i<cap_tags_length; i++) {
        if(cap_tags_map[i] == 1) {
            if(cheri_getperm(heap_ptr[i]) == 0) {
                printf("set_cap_tags_map_info error: perm = 0!\n");
                int no = (addr - heap_addr) / PAGE_SIZE;
                printf("page no  = %d, addr = %p, i = %d\n", no, addr, i);
                CHERI_CAP_PRINT(heap_ptr[i]);
                continue;
            }
            void * __capability valid_cap;
            valid_cap = invalid_to_valid((void *__capability)(heap_ptr[i]));
            ptr[i] = valid_cap;
        }
    }
}

// resume
void resume_heap_from_memory() {
    struct page *s;
    for(s=heap; s != NULL; s=s->hh.next) {
        memcpy(s->addr, s->content, PAGE_SIZE);
        set_cap_tags_map_info(s->addr, s->cap_tags, sizeof(s->cap_tags));
    }
}

static void list_dir(const char *dirPath) {
    DIR *dir;
    struct dirent *entry;
    dir = opendir(dirPath);
    if (!dir) {
        perror("opendir");
        printf("dirPath: %s\n", dirPath);
        return;
    }
    while ((entry = readdir(dir)) != NULL) {
        char fullPath[256];
        struct stat statbuf;
        snprintf(fullPath, sizeof(fullPath), "%s/%s", dirPath, entry->d_name);
        if (stat(fullPath, &statbuf) == -1) {
            perror("stat");
            continue;
        }
        if (S_ISDIR(statbuf.st_mode)) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                continue;
            }
            list_dir(fullPath);
        } else {
            struct page *s = (struct heap *)malloc(sizeof(struct page));
            if(s == NULL) {
                perror("list_dir: malloc struct page error");
                exit(EXIT_FAILURE);
            }
            read_from_heapfile(s, fullPath);
            HASH_ADD_PTR(heap, addr, s);
        }
    }
    closedir(dir);
}

void resume_heap_from_disk() {
    // copy from disk to memory
    // assume the heap is empty
    list_dir("snapshot");
    printf("resume_heap_from_disk\n");
    resume_heap_from_memory();
}
