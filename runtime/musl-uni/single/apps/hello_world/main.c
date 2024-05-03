/*#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>

#include <sys/time.h>
#include <signal.h>
#include <pthread.h>


#define _GNU_SOURCE
#include <unistd.h>
*/
#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <signal.h>


#define MSG "hello world, just a hostcall test here \n"

void app_main() {
    printf("hello world here! \n ");

    c_out_3(1, MSG, (long)sizeof(MSG), 0);
    c_out_3(1, MSG, (long)sizeof(MSG), 0);

	int i = 0;
    while(1) {
		i++;
		//printf(" times: %d \n ", i);
        //sleep(1);
		if(i==10000000) {
			i=1;
		}
    }


}