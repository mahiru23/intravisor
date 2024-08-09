#include "monitor.h"


// we need socket list & output buffer (UDP?)
// maybe written in socket_list.c, not here

// ...........
// save heap to resume program with malloc/...
// very similar to stack, reuse most code, change existed implementation

struct page *heap = NULL;
//struct page *stack = NULL;
static char *heap_dirty_page_map = NULL;
static char *heap_dirty_page_map_temp = NULL; // TODO: change syscall, we should not use it, and same in stack
static int heap_page_num;
static void *heap_addr;
static bool heap_cap_tags[256]; // 1 page
static int global_heap_fd;


char *heap_dirty_page_packet;
int global_heap_dirty_page_num;


static __inline__ int heap_addr_to_no(void *addr, void *heap_addr) {
    return ((addr - heap_addr) / PAGE_SIZE);
}

static __inline__ void *heap_no_to_addr(int no, void *heap_addr) {
    return (heap_addr + no * PAGE_SIZE);
}

void heap_page_init(int cid, int resume_flag) {

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

    if(resume_flag == NO_RESUME) {
        global_heap_fd = open("snapshot/heap_dump.bin", O_WRONLY | O_CREAT | O_TRUNC, 0777);
        if (global_heap_fd == -1) {
            perror("open");
            exit(EXIT_FAILURE);
        }  
    }  
}

void backup_heap_init() {
    makedir("snapshot");
    global_heap_fd = open("snapshot/heap_dump.bin", O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (global_heap_fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
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
            if(cheri_getperm(stack_ptr[i]) == 0) { // erro
                int tag = is_capability(stack_ptr[i]);
                printf("tag: %d\n", tag);
                printf("[capture]: heap_get_cap_info: perm = 0 !\n");
                CHERI_CAP_PRINT(stack_ptr[i]);
            }
            heap_cap_tags[i] = 1;
            sum_cap++;
        }
    }
    return sum_cap;
}

// create file for each page, save struct page
static void write_to_heapfile(int fd, struct page *s, int page_no) {

    // bitmap size: [0...heap_page_num]
    if (lseek(fd, page_no, SEEK_SET) == -1) {
        perror("write_to_heapfile lseek");
        close(fd);
        exit(EXIT_FAILURE);
    }
    if (write(fd, "1", sizeof(char)) == -1) {
        perror("write_to_heapfile write s->content");
        close(fd);
        exit(EXIT_FAILURE);
    }

    if (lseek(fd, heap_page_num + page_no*(PAGE_SIZE+PAGE_SIZE/16), SEEK_SET) == -1) {
        perror("write_to_heapfile lseek");
        close(fd);
        exit(EXIT_FAILURE);
    }
    if (write(fd, s->content, sizeof(s->content)) == -1) {
        perror("write_to_heapfile write s->content");
        close(fd);
        exit(EXIT_FAILURE);
    }

    /*if (lseek(fd, heap_page_num *(PAGE_SIZE + 1) + page_no*(PAGE_SIZE/16), SEEK_SET) == -1) {
        perror("write_to_heapfile lseek");
        close(fd);
        exit(EXIT_FAILURE);
    }*/

    if (write(fd, s->cap_tags, sizeof(s->cap_tags)) == -1) {
        perror("write_to_heapfile write s->cap_tags");
        close(fd);
        exit(EXIT_FAILURE);
    }
}

static void read_from_heapfile(int fd, struct page *s, int page_no) {

    if (lseek(fd, heap_page_num + page_no*(PAGE_SIZE+PAGE_SIZE/16), SEEK_SET) == -1) {
        perror("write_to_heapfile lseek");
        close(fd);
        exit(EXIT_FAILURE);
    }

    s->addr = heap_no_to_addr(page_no, heap_addr);

    if (read(fd, s->content, sizeof(s->content)) == -1) {
        perror("read_from_heapfile read");
        close(fd);
        exit(EXIT_FAILURE);
    }
    if (read(fd, s->cap_tags, sizeof(s->cap_tags)) == -1) {
        perror("read_from_heapfile read");
        close(fd);
        exit(EXIT_FAILURE);
    }
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

#if DEBUG
    printf("heap mincore: [%p --- %p] finish\n", addr, addr + size);
#endif

    for (int i = 0; i < page_num; i++) {
        if (dirty_page_map[i] & MINCORE_MODIFIED) {
            heap_get_cap_info(heap_no_to_addr(i, addr), PAGE_SIZE);
            struct page *s = heap_page_add_update(heap_no_to_addr(i, addr), heap_cap_tags);
            //write_to_heapfile(global_heap_fd, s, i);
            dirty_page_num++;
        #if DEBUG
            if(dirty_page_num%1000 == 0) {
                printf("now dirty_page_num: %d\n", dirty_page_num);
            }
        #endif
        }
    }

#if DEBUG
    printf("heap dirty page num before msync_manual: %d\n", dirty_page_num);
#endif

    // only support async pipeline
    if(is_master & backup_valid_flag) {
#if ASYNC_PIPELINE
        heap_dirty_page_packet = (char *)malloc(dirty_page_num*sizeof(struct page));
        if (heap_dirty_page_packet == NULL) {
            perror("malloc heap_dirty_page_packet error");
            exit(EXIT_FAILURE);
        }
        global_heap_dirty_page_num = 0;
        for (int i = 0; i < page_num; i++) {
            if (dirty_page_map[i] & MINCORE_MODIFIED) {
                struct page *s;
                void *key = heap_no_to_addr(i, addr);
                HASH_FIND_PTR(heap, &key, s);
                memcpy((void *)(heap_dirty_page_packet + global_heap_dirty_page_num*sizeof(struct page)), s, sizeof(struct page));
                global_heap_dirty_page_num++;
            }
        }
#if DEBUG
        printf("save heap_dirty_page_packet\n");
#endif
#endif
    }

    if (msync_manual(addr, size, dirty_page_map_temp) == -1) {
        perror("msync_manual heap");
        exit(EXIT_FAILURE);
    }
    return dirty_page_num;
}

// api for master
void heap_dirty_page_snapshot(void *addr, unsigned long size) {
    memory_page_update(addr, size, heap_dirty_page_map, heap_dirty_page_map_temp);
}

// for backup
void save_heap_dirty_page_to_disk(void *addr, unsigned long size) {
    int packet_page_num = size / sizeof(struct page);
    for(int i=0; i<packet_page_num; i++) {
        struct page *s = (struct heap *)malloc(sizeof(struct page));
        if(s == NULL) {
            perror("save_heap_dirty_page_to_disk: malloc struct page error");
            exit(EXIT_FAILURE);
        }
        memcpy(s, addr+i*sizeof(struct page), sizeof(struct page));
        write_to_heapfile(global_heap_fd, s, heap_addr_to_no(s->addr, heap_addr));
    }
}

// for backup
void save_heap_dirty_page_to_memory(void *addr, unsigned long size) {

    //printf("heap packet size: 0X%lx\n\n\n\n\n", size);

    int packet_page_num = size / sizeof(struct page);
    for(int i=0; i<packet_page_num; i++) {
        struct page *s_packet = (struct heap *)malloc(sizeof(struct page));
        if(s_packet == NULL) {
            perror("save_heap_dirty_page_to_memory: malloc struct page error");
            exit(EXIT_FAILURE);
        }
        memcpy(s_packet, addr+i*sizeof(struct page), sizeof(struct page));
        struct page *s_temp;
        void *key = s_packet->addr;
        HASH_FIND_PTR(heap, &key, s_temp);
        if (s_temp == NULL) {
            HASH_ADD_PTR(heap, addr, s_packet);
        } 
        else {
            memcpy(s_temp->content, s_packet->content, PAGE_SIZE);
            memcpy(s_temp->cap_tags, s_packet->cap_tags, sizeof(s_packet->cap_tags));
            free(s_packet);
        }
    }
}

void set_cap_tags_map_info(void *addr, char *cap_tags_map, int cap_tags_length) {
    uintcap_t *heap_ptr = (uintcap_t *)(addr);
    uintcap_t *ptr = (uintcap_t *)(addr);
    for (int i=0; i<cap_tags_length; i++) {
        if(cap_tags_map[i] == 1) {
            if(cheri_getperm(heap_ptr[i]) == 0) { // error addr
                printf("set_cap_tags_map_info error: perm = 0!\n");
                printf("page no  = %d, addr = %p, i = %d\n", heap_addr_to_no(addr, heap_addr), addr, i);
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
#if DEBUG
        printf("s->addr: %p, page_no: %d\n", s->addr, heap_addr_to_no(s->addr, heap_addr));
#endif
    }
    printf("resume_heap finish\n");
}


void resume_heap_from_disk() {
    // copy from disk to memory
    // assume the heap is empty

    printf("resume_heap_from_disk\n");
    int fd = open("snapshot/heap_dump.bin", O_RDWR);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    
    if (read(fd, heap_dirty_page_map, heap_page_num) == -1) {
        perror("write");
        close(fd);
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < heap_page_num; i++) {
        if (heap_dirty_page_map[i] == '1') {
            struct page *s = (struct page *)malloc(sizeof(struct page));
            if(s == NULL) {
                perror("resume_heap_from_disk: malloc struct page error");
                exit(EXIT_FAILURE);
            }
            read_from_heapfile(fd, s, i);
            HASH_ADD_PTR(heap, addr, s);
        }
    }
    close(fd);
    resume_heap_from_memory();
}
