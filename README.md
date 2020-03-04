# ElectionHacking

Useful tools and configuration files for injecting your own code into a Diebold AccuVote TSx system.
To make use of these utilities you will need an OpenOCD compatible debugger such as the TinCanTools
FlySwatter 2. You will also benefit from a PCMCIA to CompactFlash adapter and NE2000-based ethernet
PCMCIA card. You need to ensure that you get a compatible card, you can then load your own EXE or ROM
onto the Diebold AccuVote TSx system. You can also make use of the flash memory to make your adjustments
permenant. 

For more details see https://hacker.house/lab/hacking-elections-diebold-accuvote-tsx-runs-space-invaders/

WARNING: When using a CompactFlash card it must be formated with FAT16 (LBA) and can only have a maximum
size of around 32mb regardless of what size you put. mkfs.vfat will work to format the file system but its
much better to let WinCE format the disk for you, providing you set the file header up it will do that
on initial boot.

