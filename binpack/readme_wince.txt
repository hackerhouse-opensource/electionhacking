Netcat for WINCE

A VERY USEFULL network tool! A 'swiss army knife' 4 small devices!

The original version of Netcat was written by *hobbit* <hobbit@avian.org>
The NT version was done by Weld Pond <weld@l0pht.com>
The WINCE version was done by Andreas Bischoff <andreas.bischoff@fernuni-hagen.de>
The port uses the !great! CELIB created by Rainer Keukel.

> New for NT
>
>     * Ability to run in the background without a console window
>     * Ability to restart as a single-threaded server to handle a new
>       connection

The new features for NT doesn't work for CE!

To install the netcat tool, just copy the required celib.dll (see http://www.rainer-keuchel.de/wince/celib.html )
(and ONLY for wince 2.00 [and 2.01.]) MSVCRT.DLL (included for sh3 wince 2.0 version) to your windows directory.
Copy NC.EXE to any directory you like. 

If you start NC.EXE it will open a console window and prompt for the Command options. It is also possible to use
the tool inside Rainer Keukels great w32console tool. Maybe you have to set environment vars (see http://www.rainer-keuchel.de/wince/console.html ). 

For instance:

w23console.exe
# nc -l -p 23 -o \speicherkarte\test.out   starts a listener on port 23 (telnet) and dumps all the incommig
traffic to the file "test.out".

Problems:
The wince netcat behaviour is a little bit different than the win32 one.
If nc.exe is not listener ('-l') the '-v' option is required for connection to the windows netcat version, 
connections to the unix version are uncritical, don't know why. The same problem happens when you connet with -t to a UNIX-telnet-server, also try -v. UDP and piping are currently untested.
-e option doesn't work currently under ce

Usage:
The original readme's for UNIX and Windows are included (nice netcat tutorials readme.unix and readme.nt).

Simply try a portscan:

nc -v -w 2 -z <unix-box-name> 20-30

or connect two wince or wince to unix or nt boxes:
server:
nv -l -p 100
client:
nc -v serverboxname 100

Netcat acts as client or as server!

Have fun!

Andreas 12/2002
