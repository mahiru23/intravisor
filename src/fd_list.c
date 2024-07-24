#include "monitor.h"

#define MAX_FD_NUMS 10
#define FD_NAME_LEN 40

// use dup/dup2 maintain fd state
// need to maintain in master/backup intravisor (with file ops)
// keep relative sync between master & backup (each checkpoint)
struct fd_info {
	int fd;
    int offset;
    char pathname[FD_NAME_LEN];
    int flags;
    mode_t mode;
};
static struct fd_info open_fd_list[MAX_FD_NUMS];
static pthread_mutex_t fd_store_lock;

void init_fd_store() {
	memset(open_fd_list, 0, MAX_FD_NUMS * sizeof(struct fd_info));
	if(pthread_mutex_init(&fd_store_lock, NULL) != 0) {
		printf("\n mutex init failed\n");
		while(1) ;
	}
    for(int i=0; i<MAX_FD_NUMS; i++) {
        open_fd_list[i].fd = -1;
    }
}

void clear_fd_list() {
    pthread_mutex_lock(&fd_store_lock);
    for(int i=0; i<MAX_FD_NUMS; i++) {
        if(open_fd_list[i].fd != -1) {
            open_fd_list[i].fd = -1;
        }
    }
    pthread_mutex_unlock(&fd_store_lock);
}

int close_fd(int fd) {
    pthread_mutex_lock(&fd_store_lock);
    int i = 0;
    for(i=0; i<MAX_FD_NUMS; i++) {
        if(open_fd_list[i].fd == fd) {
            open_fd_list[i].fd = -1;
            break;
        }
    }

	if(i == MAX_FD_NUMS) {
		printf("close_fd: cannot find fd:%d, die\n", fd);
		while(1) ;
	}

    pthread_mutex_unlock(&fd_store_lock);
    return 0;
}

int open_fd(int fd, const char *pathname, int flags, mode_t mode) {
    if(strlen(pathname) > FD_NAME_LEN) {
        printf("pathname is too long!\n");
        exit(-1);
    }
    pthread_mutex_lock(&fd_store_lock);
    int i = 0;
    for(i=0; i<MAX_FD_NUMS; i++) {
        if(open_fd_list[i].fd == -1) {
            open_fd_list[i].fd = fd;
            open_fd_list[i].offset = 0;
            open_fd_list[i].flags = flags;
            open_fd_list[i].mode = mode;
            strcpy(open_fd_list[i].pathname, pathname);
            break;
        }
    }

	if(i == MAX_FD_NUMS) {
		printf("open_fd: no empty fd position in fd_list, die, MAX_FD_NUMS: %d\n", MAX_FD_NUMS);
		while(1) ;
	}
    pthread_mutex_unlock(&fd_store_lock);
    return 0;
}

void update_offset() {
    pthread_mutex_lock(&fd_store_lock);
    for(int i=0; i<MAX_FD_NUMS; i++) {
        if(open_fd_list[i].fd != -1) {
            off_t current_pos = lseek(open_fd_list[i].fd, 0, SEEK_CUR);
            if (current_pos == -1) {
                perror("Failed to get current file position");
                exit(-1);
            }
            open_fd_list[i].offset = current_pos;
        }
    }
    pthread_mutex_unlock(&fd_store_lock);
}

void save_fd_list_snapshot() {
    update_offset();
    pthread_mutex_lock(&fd_store_lock);
    int fd = open("snapshot/fd_list.bin", O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    if (write(fd, open_fd_list, MAX_FD_NUMS * sizeof(struct fd_info)) == -1) {
        perror("write");
        close(fd);
        exit(EXIT_FAILURE);
    }
    close(fd);
    pthread_mutex_unlock(&fd_store_lock);
}

void memcpy_fd_list(void *dest, int len) {
    memcpy(dest, (void *)open_fd_list, len);
}

// only in backup memory
int open_fd_backup(int master_fd, const char *pathname, int flags, mode_t mode) {
    int backup_fd = open(pathname, flags, mode);
    if (backup_fd == -1) {
        perror("backup_fd open");
        exit(EXIT_FAILURE);
    }
#if DEBUG
    printf("pathname: %s\n", pathname);
    printf("backup_fd: %d, master_fd: %d\n", backup_fd, master_fd);
#endif
    if (dup2(backup_fd, master_fd) < 0) {
        perror("dup2");
        close(backup_fd);
        return -1;
    }
    return 0;
}

void save_fd_list_backup(void *addr) {
    memcpy((void *)open_fd_list, addr, MAX_FD_NUMS * sizeof(struct fd_info));
}

void resume_fd_list_from_snapshot() {
    int fd = open("snapshot/fd_list.bin", O_RDWR);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    if (read(fd, open_fd_list, MAX_FD_NUMS * sizeof(struct fd_info)) == -1) {
        perror("read open_fd_list");
        close(fd);
        exit(EXIT_FAILURE);
    }
    close(fd);

    for(int i=0; i<MAX_FD_NUMS; i++) {
        if(open_fd_list[i].fd != -1) {
            open_fd_backup(open_fd_list[i].fd, open_fd_list[i].pathname, open_fd_list[i].flags, open_fd_list[i].mode);
            if (lseek(fd, open_fd_list[i].offset, SEEK_SET) == -1) {
                perror("Failed to seek offset");
                exit(EXIT_FAILURE);
            }
        }
    }
}

int open_fd_list_size() {
    return MAX_FD_NUMS * sizeof(struct fd_info);
}
