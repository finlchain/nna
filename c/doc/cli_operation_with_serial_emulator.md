0. Pre-requisite
	Install "socat" and "minicom" in your Linux System
	
	sudo yum install socat
	sudo yum install minicom

1. Make dev folder in your home directory
	e.g.) /home/mofas/dev
	
2. Edit "cli.lua" file on "conf" folder for "ttyV0" and "ttyV1"
	e.g.) 
	CLI = {
		PATH = {
			TTY_0 = "/home/mofas/dev/ttyV0",
			TTY_1 = "/home/mofas/dev/ttyV1",
		},
	}
	
3. Compile and Run your program
	after changing as "#define CLI_SERIAL_EMULATOR ENABLED" in "cli.cpp" folder

4. Then, you can get newly opened gnome-terminal and see below message
	e.g.)
	2019/02/11 11:29:51 socat[23003] N PTY is /dev/pts/4
	2019/02/11 11:29:51 socat[23003] N PTY is /dev/pts/5
	2019/02/11 11:29:51 socat[23003] N starting data transfer loop with FDs [5,5] and [7,7]
	
5. Run minicom using below command
	See second line on number 4. "/dev/pts/5"
		The port should be used on minicom side.
	e.g.)
	minicom -b 115200 -D /dev/pts/5
	
6. Type cli command in minicom windows
	e.g.)
	eddsa

