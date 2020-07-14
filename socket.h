#define BOOL unsigned long

#ifndef __sockets_h__
#define __sockets_h__

#define REUSE_SOCKETSIRP

// debugprint with debuglevel (if dbglevel == debug level, it triggers)
#if DBG
#define KDebugPrint(DbgLevel,_x) { if (DbgLevel == DEBUG_LEVEL){DbgPrint _x;}}
#else
#define KDebugPrint(DbgLevel,_x)
#endif //DBG

//#define ALWAYS_DISABLESOCKETS

//************************************************************************
// kernel sockets                                                                     
//                                                                      
//************************************************************************/
PDEVICE_OBJECT            TcpIpDevice;

typedef struct __tagKSOCKET
{
    PFILE_OBJECT                TransportAddress;
    HANDLE                        TransportAddressHandle;
    PFILE_OBJECT                ConnectionFile;
    HANDLE                        ConnectionFileHandle;
    BOOLEAN                        Connected;
}KSOCKET, * PKSOCKET;

typedef struct _tagKSOCKET_CTX {
    KEVENT Event;
    IO_STATUS_BLOCK Iosb;
} KSOCKET_CTX, *PKSOCKET_CTX;

PAGED_LOOKASIDE_LIST    LookasideSocketMem;
PAGED_LOOKASIDE_LIST    LookasideSocket;
KEVENT                    NoNetworkFailures;
BOOLEAN                    DisableSockets;                    // flag to disable sockets if needed
PDRIVER_DISPATCH        OriginalTcpInternalDeviceControl;
PIRP                    SocketsIrp;

// all paged code except the completion routine
BOOL                    KSocketInitialize();
#pragma alloc_text        (PAGEboom,KSocketInitialize)

NTSTATUS                KSocketCreate(OUT PKSOCKET* Socket);

NTSTATUS				KSocketCreateAndBind(OUT PKSOCKET* Socket, IN USHORT sin_port, IN ULONG  in_addr);

VOID                    KSocketClose(PKSOCKET Socket);

PVOID                   KSocketAllocatePool();

void                    KSocketFreePool(PVOID pBuffer);

NTSTATUS                KSocketSend(PKSOCKET pSocket, PVOID  Buffer, SIZE_T Size,
                                    PSIZE_T BytesSent);

NTSTATUS                KSocketConnect(PKSOCKET pSocket, ULONG Address, USHORT Port);
NTSTATUS				KSocketListen(PKSOCKET pSocket);
NTSTATUS                KSocketDisconnect(PKSOCKET pSocket);

NTSTATUS                KSocketComplete(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context);

NTSTATUS                KSocketReceive(PKSOCKET pSocket, PVOID Buffer, SIZE_T Size, PSIZE_T BytesReceived,
                            BOOLEAN ReceivePeek);

NTSTATUS                KSocketReadLine(PKSOCKET pSocket, PCHAR buf, SIZE_T maxlen, PSIZE_T  ReceivedBytes);

NTSTATUS                KSocketWriteLine(PKSOCKET pSocket, const char* format, ...);

#endif // __sockets_h__