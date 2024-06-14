./install.sh cheribsd/ $HOME/cheri/cheribsd/
./install.sh dirtycap/ $HOME/cheri/cheribsd/

sysctl -a | grep aslr

sysctl kern.elf64.aslr.stack=0;
sysctl kern.elf64.aslr.pie_enable=0
sysctl kern.elf64.aslr.enable=0
sysctl kern.elf64c.aslr.stack=0
sysctl kern.elf64c.aslr.pie_enable=0
sysctl kern.elf64c.aslr.enable=0


