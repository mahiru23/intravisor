
# Continuous VM replication

This project builds upon the existing [Intravisor 0.3.0](https://github.com/lsds/intravisor) (commit ID: d030ac3b8bbc2a7148ac3c3a68e2b99fb87378cd), adding continuous replication features and extending several submodules.

Our repository link: https://github.com/mahiru23/intravisor/tree/syscall

## Intravisor extension
Significant modifications were made to the following files:
- main.c : support replication and disaster recovery
- utils.c : public tools
- host_cap_files.c : snapshot and resume capfiles
- monitor.h : modified queue implementation, configurations and global variables
- /riscv/asm.S : add RISC-V code to fill aux

Adding the following files:
- pipeline.c : normal synchronous pipeline implementation
- async_pipeline.c : pipeline implementation with asynchronous transmission
- replication.c : capture snapshot 
- resume_cvm.c : recovery cVM service from snapshot
- fd_list.c : maintain file descriptor and write operations
- heap_snapshot.c : memory management and dirty page tracking

This project also introduced the third-party library [uthash](https://github.com/troydhanson/uthash/tree/master).

## CheriBSD kernel patches
The [CheriBSD](https://github.com/CTSRD-CHERI/cheribsd/tree/main) kernel version is cheri-rel-20220713 (commit ID: ed75299cb9f093c5aa3c7ea5ed0ed745b7de5630). The kernel patches are stored in the extra_syscall directory, primarily modifying the ULE scheduler and MMU, adding new syscalls, and providing libc interfaces.



# Manual
## Install kernel patches

```
cd intravisor/src/extra_syscall/  
./install.sh cheribsd/ $HOME/cheri/cheribsd/  
./install.sh dirtycap/ $HOME/cheri/cheribsd/  
cd cheribuild/  
./cheribuild.py run-riscv64-hybrid --enable-hybrid-targets -d  
```

## Start

```
qemu-mount-rootfs.sh  
```

## Disable ASLR

```
sysctl kern.elf64.aslr.stack=0  
sysctl kern.elf64.aslr.pie_enable=0  
sysctl kern.elf64.aslr.enable=0  
sysctl kern.elf64c.aslr.stack=0  
sysctl kern.elf64c.aslr.pie_enable=0  
sysctl kern.elf64c.aslr.enable=0  
sysctl -a | grep aslr  
```

## Demo

```
cp -r /outputroot/intravisor /  
cd /intravisor  
mkdir /intravisor/backup/  
chmod 777 /intravisor/backup/  
cp -r /intravisor/intravisor /intravisor/backup/  
cp -r /intravisor/libhello_world.so /intravisor/backup/ ; cp -r /intravisor/musl-uni-hello.yaml /intravisor/backup/ ; cp -r /intravisor/musl-uni-hello.ci /intravisor/backup/  
```

### Snapshot test

```
./intravisor -y musl-uni-hello.yaml  
./intravisor --resume musl-uni-hello.yaml  
```

### Pipeline test

```
cd /intravisor/backup  
./intravisor -b musl-uni-hello.yaml &  
ps -ef | grep intravisor  
cd /intravisor  
./intravisor -n -y musl-uni-hello.yaml  
```


## Benchmark

```
make -C runtime/musl-uni/single/  
make -C runtime/musl-uni/single/apps/benchmark -j 8  
make -C runtime/musl-uni/single/apps/benchmark install INSTALL_PATH=~/cheri/output/intravisor/  

cp -r /outputroot/intravisor/libbenchmark.so /intravisor/ ; cp -r /outputroot/intravisor/benchmark.yaml /intravisor/ ; cp -r /outputroot/intravisor/benchmark.ci /intravisor/  
```


## Default config
### Timeout
```
#define HEARTBEAT_TIMEOUT_SEC 0
#define HEARTBEAT_TIMEOUT_USEC 50000

#define DISCONNECTION_TIMEOUT_SEC 15
#define DISCONNECTION_TIMEOUT_USEC 0

#define QUEUE_TIMEOUT_SEC 1
#define QUEUE_TIMEOUT_USEC 0

#define QUEUE_EMPTY_TIMEOUT_USEC 50000
```

### System options
```
#define SNAPSHOT 1
#define HEAP_SNAPSHOT 1
#define SMALL_HEAP 1
#define SMALL_HEAP_SIZE 1026

#define DEBUG 0
#define ANALYSE 1
#define ASYNC_PIPELINE 1
#define RANDOM_CRASH 0
#define RANDOM_CRASH_TIMEOUT_SEC 1
```


### Software parameters

```
-n / --network  # setup primary host network and initialize replication service
-b / --backup   # setup backup host network and initialize listener service
-y / --yaml     # select yaml 
--resume        # recovery from snapshot
--interval      # set heartbeat interval
--latency       # set network latency and packet loss rate [only for test]
```


