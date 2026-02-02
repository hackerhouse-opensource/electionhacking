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

An RSA private key was extracted from the ROM, using the name "ballotstation.pem", it made use of a 
hardcoded password inside of BalletStation.exe, the certificate password is shown here:

        001c02d8 62 00 61        unicode    u"ballotstation.pem"
                 00 6c 00 
                 6c 00 6f 
        001c02fc 75 00 68        unicode    u"uhn#8xgY!kY:'abN"
                 00 6e 00 
                 23 00 38 

Format a W95 FAT16 (LBA) compactflash or similar storage device accessible via PCMCIA. Copy the cf_card
folder contents to the compactflash disk. The following utilities are included:

* CEProcessV.exe    - process manager
* Doom.exe          - doom (crashes natively, use over RDP)
* FreqTune.exe      - frequency tuner test app
* TascalFiler.exe   - file manager
* TascalRegEdit.exe - registry editor
* TaskMgrARM.exe    - process manager
* cb64CE.exe        - commodore64 emulator
* invaders.exe      - space invaders 
* mstsc.exe         - rdp client
* nc.exe            - netcat
* nesCE.exe         - NES emulator
* ramfiles.exe      - ram filesystem

# License

These files are available under the 3-clause BSD license.
