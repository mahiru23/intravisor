./install.sh cheribsd/ $HOME/cheri/cheribsd/
./install.sh dirtycap/ $HOME/cheri/cheribsd/

sysctl -a | grep aslr

sysctl kern.elf64.aslr.stack=0;
sysctl kern.elf64.aslr.pie_enable=0
sysctl kern.elf64.aslr.enable=0
sysctl kern.elf64c.aslr.stack=0
sysctl kern.elf64c.aslr.pie_enable=0
sysctl kern.elf64c.aslr.enable=0



dirtycap support added in commit https://github.com/CTSRD-CHERI/cheribsd/pull/1754
make some modifies, may not works



