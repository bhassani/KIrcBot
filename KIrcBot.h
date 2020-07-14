/*
	Kernel Ircbot Framework
    (c) Tibbar 2006.  If you wish to use this code in your own project please contact me
	at tibbar@tibbar.org to obtain permission.
*/

#ifdef KERNELMODE
#include "ntddk.h"
#include "socket.h"
#include "tdi.h"
#include "unixwrap.h"
#else
#include "windows.h"
#include "usermodewrap.h"
#endif

#define RELATIVE(wait) (-(wait))

#define NANOSECONDS(nanos) \
(((signed __int64)(nanos)) / 100L)

#define MICROSECONDS(micros) \
(((signed __int64)(micros)) * NANOSECONDS(1000L))

#define MILLISECONDS(milli) \
(((signed __int64)(milli)) * MICROSECONDS(1000L))

 #define SECONDS(seconds) \
(((signed __int64)(seconds)) * MILLISECONDS(1000L))

 #define MINUTES(minutes) \
(((signed __int64)(minutes)) * SECONDS(60L))


BOOL irc_parseline(PKSOCKET pKSocket, char* readBufferLine);
void irc_connect(PKSOCKET pKSocket);
void irc_connect(PKSOCKET pKSocket);
void OpenListener();
void irc_initialise();

