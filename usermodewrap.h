/*
	Kernel Ircbot Framework
    (c) Tibbar 2006.  If you wish to use this code in your own project please contact me
	at tibbar@tibbar.org to obtain permission.
*/

#include "windows.h"
#include <stdio.h>

#define PDEVICE_OBJECT PVOID
#define PDRIVER_OBJECT PVOID

#define PKSOCKET SOCKET

#define NTSTATUS LONG

#define STATUS_SUCCESS                          ((NTSTATUS)0x00000000L) 

void DbgPrint(char* msg)
{
	printf("%s",msg);
}

NTSTATUS KSocketGetLastError()
{
	int error = WSAGetLastError();
	if( error == 0) return STATUS_SUCCESS;
	return (NTSTATUS)error;

}

BOOL KSocketInitialize(void)
{
	WSADATA wsaData;
	int diditwork = WSAStartup(MAKEWORD( 2, 2 ),&wsaData);
	if(diditwork ==0) return TRUE;
	return FALSE;
}

#define PagedPool 1
PVOID ExAllocatePoolWithTag(int p, int size, int name)
{
	return malloc(size);
}

void ExFreePoolWithTag(PVOID pointer, int name)
{
	free(pointer);
}

#define KernelMode 1

void KeDelayExecutionThread(int a, BOOL b, PLARGE_INTEGER waitTime)
{
	Sleep(50);
}

int KSocketReadLine(PKSOCKET socket, char* buf, SIZE_T maxlen, PSIZE_T ReceivedBytes)
{
    int Status = -1;
    char c = 0;
    ULONG i = 0;


    // check params
    if (!buf || !ReceivedBytes || !maxlen)
        goto __exit;
    
    *ReceivedBytes = 0;
    
    // read line char by char, and stop at EOL
    memset (buf, 0, maxlen);
    while (TRUE)
    {
        if (i == maxlen)
            break;
        
        // get char from socket
		Status = recv(socket, &c, 1, 0);
        if (Status == SOCKET_ERROR || Status == 0 )
		{
			Status = -1;
            break;
		}
        
        // write char into buffer and advance
        *buf = c;
        buf++;
        i++;
        
        // check for EOL
        if (c == '\n')
        {
            *ReceivedBytes = i;
            break;
        }
    }
    
__exit:

    if(Status == 1 ) return 0;
    return Status;
}