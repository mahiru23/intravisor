#include "crt.h"
#include "hostcalls.h"

#define MSG "hello world from inner \n"

void hello_c() {
	char buf[32];
	char cap[16]; //place to store the capability

	host_write(MSG, sizeof(MSG));

	host_exit();
}

