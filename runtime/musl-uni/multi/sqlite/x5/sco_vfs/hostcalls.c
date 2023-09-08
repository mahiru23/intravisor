#include "hostcalls.h"

extern long c_out(void *);

int host_write_out(char *ptr, int size) {
#if 0
	int tmp = 1;
	register long t5 __asm__("t5") = tmp;
	register long a0 __asm__("a0") = (long) ptr;
	register long a1 __asm__("a1") = (long) size;

	__asm__ __volatile__("cjr %4" : "=r"(a0) : "r"(t5), "r"(a0), "r"(a1), "C"(c_out) : "memory" );
	return (int) a0; 

#else
	return (int) c_out_3(1, ptr, (long) size, 0);
#endif
}

int host_get_sc_caps(int me, int they, void *ptr) {
	return c_out_3(702, me, they, ptr);
}

void ramfs_caps_init() {
	c_out_3(750, 0, 0, 0);
}

void nolibc_caps_init() {
	c_out_3(752, 0, 0, 0);
}

///////////////////////

int host_gettimeofday(void *ptr, void *ptr2) {
#if 0
	int tmp = 1;
	register long t5 __asm__("t5") = tmp;
	register long a0 __asm__("a0") = (long) ptr;
	register long a1 __asm__("a1") = (long) ptr2;

	__asm__ __volatile__("jal c_out" : "=r"(a0) : "r"(t5), "r"(a0), "r"(a1) : "memory" );
	return a0; 

#else
	return c_out_3(800, (long) ptr, (long) ptr2, 0);
#endif


}

int host_lstat(const char *pathname, struct stat *statbuf) {
	return (int) c_out_3(801, (long) pathname, (long) statbuf, 0);
}
int host_stat(const char *pathname, struct stat *statbuf) {
	return c_out_3(806, (long) pathname, (long) statbuf, 0);
}
int host_fstat(int fd, struct stat *statbuf) {
	return c_out_3(807, fd, (long) statbuf, 0);
}

int host_unlink(const char *pathname) {
	return (int) c_out_3(802, (long) pathname, 0, 0);
}
int host_close(int fd) {
	return (int) c_out_3(803, fd, 0, 0);
}
int host_access(const char *pathname, int mode) {
	return (int) c_out_3(804, (long) pathname, mode, 0);
}

int host_truncate(const char *path, size_t length) {
	return c_out_3(808, (long) path, length, 0);
}
__ssize_t host_read(int fd, void *buf, size_t count) {
	return c_out_3(809, fd, (long) buf, count);
}
__ssize_t host_write(int fd, const void *buf, size_t count) {
	return c_out_3(810, fd, (long) buf, count);
}
int host_open(const char *pathname, int flags, mode_t mode) {
	return c_out_3(811, (long) pathname, flags, mode);
}

off_t host_lseek(int fd, off_t offset, int whence) {
	return (off_t) c_out_3(812, fd, offset, whence);
}

int host_get_errno() {
	return c_out_3(813, 0, 0, 0);
}

int host_fcntl(int fd, int cmd, long *ptr ) {
	return c_out_3(813, fd, cmd, ptr);
}


////////////////////////

void host_exit() {
#if 0
	int tmp = 13;
	register long a0 __asm__("a0");
	register long t5 __asm__("t5") = tmp;

	__asm__ __volatile__("jal c_out" : "=r"(a0) : "r"(t5) : "memory" );
#else
	c_out_3(13, 0, 0, 0);
#endif
}

int host_cap_prb(char *key, void *location) {
#if 0
	int tmp = 406;
	register long a0 __asm__("a0") = (long) key;
	register long a1 __asm__("a1") = (long) location;
	register long t5 __asm__("t5") = tmp;
	__asm__ __volatile__("jal c_out" : "=r"(a0) : "r"(t5), "r"(a0), "r"(a1) : "memory" );
	return (int) a0; 
#else
	return c_out_3(406, (long) key, (long) location, 0);
#endif
}


int host_get_my_inner(void *ptr) {
#if 0
	int tmp = 700;
	register long t5 __asm__("t5") = tmp;
	register long a0 __asm__("a0") = (long) ptr;

	__asm__ __volatile__("jal c_out" : "=r"(a0) : "r"(t5), "r"(a0) : "memory" );
	return (int) a0;
#else
	return c_out_3(700, (long) ptr, 0, 0);
#endif
}

int host_syscall_handler_prb(char *name, void *a, void *b, void *c) {
	return c_out_5(701, name, a, b, c, 0);
}
