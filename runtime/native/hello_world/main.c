#include "hostcalls.h"

#define MSG "hello flag 1 \n"

#define MSG2 "hello flag 2 \n"

void out_c() {
	char buf[32];
	char cap[16];		//place to store the capability
	long size;


	while(1) {
		get_test();
	}

	
	host_exit();



	host_write_out(MSG, sizeof(MSG));

	//host_cap_prb("test1", cap, &size);

	//copy_from_cap(buf, cap, 32);

	host_save();

	host_write_out(MSG2, sizeof(MSG2));

	//host_write_out(buf, 32);

	host_exit();
}
