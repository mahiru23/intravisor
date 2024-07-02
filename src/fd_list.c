#include "monitor.h"

#define MAX_FD_NUMS	10

// use dup/dup2 maintain fd state
// need to maintain in master/backup intravisor (with file ops)
// keep relative sync between master & backup (each checkpoint)
struct master_backup_fd_pair {
    int valid;
	int master_fd;
    int backup_fd;
};
static struct master_backup_fd_pair open_fd_list[MAX_FD_NUMS];
static pthread_mutex_t fd_store_lock;

void init_fd_store() {
	memset(open_fd_list, 0, MAX_FD_NUMS * sizeof(struct master_backup_fd_pair));
	if(pthread_mutex_init(&fd_store_lock, NULL) != 0) {
		printf("\n mutex init failed\n");
		while(1) ;
	}
}

int find_backup_fd(int master_fd) {
    for(int i=0; i<MAX_FD_NUMS; i++) {
        if(open_fd_list[i].master_fd == master_fd) {
            return open_fd_list[i].backup_fd;
        }
    }
    return -1;
}

void clear_fd_list() {
    for(int i=0; i<MAX_FD_NUMS; i++) {
        if(open_fd_list[i].valid == 1) {
            close(open_fd_list[i].backup_fd);
            open_fd_list[i].valid = 0;
            open_fd_list[i].master_fd = 0;
            open_fd_list[i].backup_fd = 0;
        }
    }
}

int close_fd(int master_fd) {
    for(int i=0; i<MAX_FD_NUMS; i++) {
        if(open_fd_list[i].valid == 1 && open_fd_list[i].master_fd == master_fd) {
            close(open_fd_list[i].backup_fd);
            open_fd_list[i].valid = 0;
            open_fd_list[i].master_fd = 0;
            open_fd_list[i].backup_fd = 0;
            return 0;
        }
    }
    return -1;
}

int open_fd(int master_fd, const char *pathname, int flags, mode_t mode) {
    for(int i=0; i<MAX_FD_NUMS; i++) {
        if(open_fd_list[i].valid == 0) {
            int backup_fd = open(pathname, flags, mode);
            if (backup_fd == -1) {
                perror("backup_fd open");
                exit(EXIT_FAILURE);
            }
            open_fd_list[i].valid = 1;
            open_fd_list[i].master_fd = master_fd;
            open_fd_list[i].backup_fd = backup_fd;
            return 0;
        }
    }
    return -1;
}






