/*
	Unix wrappers for Valerino's socket library
	(c) Tibbar 2006.  If you wish to use this code in your own project please contact me
	at tibbar@tibbar.org to obtain permission.
*/
#ifdef KERNELMODE

#include "ntifs.h"
#include "tdi.h"
#include "tdikrnl.h"
#include "tdiinfo.h"

#include "socket.h"
#include "unixwrap.h"

/*
	Globals
*/
NTSTATUS lastSocketError = STATUS_SUCCESS;




/*
	Error reporting function for kernel sockets
*/

NTSTATUS KSocketGetLastError(void)
{
	return lastSocketError;
}

void KSocketSetError(NTSTATUS errorCode)
{
	lastSocketError = errorCode;
}


/*
	Unix socket wrappers
*/


/*
	KSocket:
	NTSTATUS                KSocketCreate(OUT PKSOCKET* Socket);
	unix:
	int socket(int domain, int type, int protocol);

	We only support domain = PF_INET, type = SOCK_STREAM, protocol = IPPROTO_TCP at moment
*/

PKSOCKET socket(int domain, int type, int protocol)
{
	NTSTATUS status = STATUS_SUCCESS;
	PKSOCKET pKSocket = NULL;

	if(domain !=PF_INET && type != SOCK_STREAM && protocol != 1)
	{
		KSocketSetError(-1);
		return NULL;
	}

	status = KSocketCreate(&pKSocket);

	KSocketSetError(status);

	return pKSocket;
}

/*
	KSocket:
	NTSTATUS KSocketCreateAndBind(OUT PKSOCKET* Socket, IN USHORT sin_port, IN ULONG  in_addr);
	unix: (not exist, combination of socket and bind)
	int socket(int domain, int type, int protocol);
	int bind( SOCKET s, const struct sockaddr* name, int namelen);

	We only support domain = PF_INET, type = SOCK_STREAM, protocol = IPPROTO_TCP at moment
*/

PKSOCKET socketbind(USHORT sin_port, ULONG  in_addr)
{
	NTSTATUS status = STATUS_SUCCESS;
	PKSOCKET pKSocket = NULL;

	if(sin_port == 0 || in_addr ==0)
	{
		KSocketSetError(-1);
		return NULL;
	}

	status = KSocketCreateAndBind(&pKSocket, sin_port, in_addr);

	KSocketSetError(status);

	return pKSocket;
}



/*
	KSocket: NTSTATUS KSocketConnect(PKSOCKET pSocket, ULONG Address, USHORT Port);
	unix: int connect(int sockfd, const struct sockaddr *serv_addr, socklen_t addrlen);  
*/

int connect(PKSOCKET pSocket, const struct sockaddr_in *serv_addr, int namelen)
{
	NTSTATUS status = STATUS_SUCCESS;
	if(serv_addr == NULL || pSocket == NULL)
	{
		return SOCKET_ERROR;
	}
	status = KSocketConnect(pSocket, serv_addr->sin_addr.S_un.S_addr, serv_addr->sin_port);
	KSocketSetError(status);

	if(status == STATUS_SUCCESS) return 0;
	return SOCKET_ERROR;
}


/*
	KSocket: NTSTATUS KSocketListen(PKSOCKET pSocket);
	unix: int listen(SOCKET s,int backlog);
*/
int listen(PKSOCKET s,int backlog)
{
	NTSTATUS status = STATUS_SUCCESS;
	if(s == NULL)
	{
		return SOCKET_ERROR;
	}
	status = KSocketListen(s);
	KSocketSetError(status);

	if(status == STATUS_SUCCESS) return 0;
	return SOCKET_ERROR;
}

/*
	Ksocket: NTSTATUS KSocketDisconnect(PKSOCKET pSocket)	
	unix: int shutdown(SOCKET s, how);
	(polite closing of socket)
*/
int shutdown(PKSOCKET pSocket, int how)
{
	NTSTATUS status = STATUS_SUCCESS;
	KSocketDisconnect(pSocket);
	KSocketClose(pSocket);
	KSocketSetError(status);
	if(status == STATUS_SUCCESS) return 0;
	return SOCKET_ERROR;
}

/*
	KSocket: VOID KSocketClose(PKSOCKET Socket);
	unix: int closesocket(  SOCKET s);
	(impolite socket close)
*/
int closesocket(PKSOCKET pSocket)
{
	NTSTATUS status = STATUS_SUCCESS;
	KSocketClose(pSocket);
	KSocketSetError(status);
	if(status == STATUS_SUCCESS) return 0;
	return SOCKET_ERROR;	
}

/*
	KSocket: NTSTATUS KSocketSend(PKSOCKET pSocket, PVOID  Buffer, SIZE_T Size,
                                    PSIZE_T BytesSent);
	unix: int send(	  SOCKET s,
					  const char* buf,
					  int len,
					  int flags);
*/
int send(PKSOCKET pSocket, const char* buf, int len, int flags)
{
	NTSTATUS status = STATUS_SUCCESS;
	SIZE_T BytesSent;
	
	status = KSocketSend(pSocket, (PVOID)  buf, (SIZE_T) len, &BytesSent);
	KSocketSetError(status);
	if(status == STATUS_SUCCESS) return 0;
	return SOCKET_ERROR;
}

/*
	KSockets: NTSTATUS KSocketReceive(PKSOCKET pSocket, PVOID Buffer, SIZE_T Size, PSIZE_T BytesReceived,
                                      BOOLEAN ReceivePeek);
	unix: int recv(SOCKET s, char* buf, int len, int flags);
*/

int recv(PKSOCKET pSocket, char* buf, int len, int flags)
{
	NTSTATUS status = STATUS_SUCCESS;
	SIZE_T BytesReceived;

	status = KSocketReceive(pSocket, (PVOID) buf, (SIZE_T) len, &BytesReceived, (BOOLEAN) flags);

	KSocketSetError(status);
	if(status == STATUS_SUCCESS) return (int)BytesReceived;
	return SOCKET_ERROR;
}

#endif