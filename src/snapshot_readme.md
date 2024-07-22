

# install kernel patch
cd intravisor/src/extra_syscall/  
./install.sh cheribsd/ $HOME/cheri/cheribsd/  
./install.sh dirtycap/ $HOME/cheri/cheribsd/  
cd cheribuild/  
./cheribuild.py run-riscv64-hybrid --enable-hybrid-targets -d  

# start
qemu-mount-rootfs.sh  

# disable ASLR

sysctl kern.elf64.aslr.stack=0  
sysctl kern.elf64.aslr.pie_enable=0  
sysctl kern.elf64.aslr.enable=0  
sysctl kern.elf64c.aslr.stack=0  
sysctl kern.elf64c.aslr.pie_enable=0  
sysctl kern.elf64c.aslr.enable=0  
sysctl -a | grep aslr  

# install

cp -r /outputroot/intravisor /  
cd /intravisor  
mkdir /intravisor/backup/  
chmod 777 /intravisor/backup/  
cp -r /intravisor/intravisor /intravisor/backup/  
cp -r /intravisor/libhello_world.so /intravisor/backup/ ; cp -r /intravisor/musl-uni-hello.yaml /intravisor/backup/ ; cp -r /intravisor/musl-uni-hello.ci /intravisor/backup/  


# snapshot test

./intravisor -y musl-uni-hello.yaml  
./intravisor --resume musl-uni-hello.yaml  


# pipeline test

cd /intravisor/backup  
./intravisor -b musl-uni-hello.yaml &  
ps -ef | grep intravisor  
cd /intravisor  
./intravisor -n -y musl-uni-hello.yaml  
