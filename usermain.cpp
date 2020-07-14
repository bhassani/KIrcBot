/*
	Kernel Ircbot Framework
    (c) Tibbar 2006.  If you wish to use this code in your own project please contact me
	at tibbar@tibbar.org to obtain permission.
*/

#ifndef KERNELMODE

#include <iostream>
#include <tchar.h>
#include "windows.h"


extern "C" void irc_initialise(void);


int main(int argc, char* argv[])
{
	irc_initialise();

	return 0;
}

#endif