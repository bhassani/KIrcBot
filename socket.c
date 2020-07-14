#ifdef KERNELMODE
//************************************************************************
//                                                                      
// sockets.c
// (c) valerino/xOANINO 2003/2004/2005
//
// this module implements a generic kernel sockets library.
// ** Beware that this is optimized for single thread use if REUSE_SOCKETSIRP is defined.**
//*****************************************************************************

// Tibbar: Added some minor code from linux sockets to handle ip address formatting.

#define REUSE_SOCKETSIRP

#include "ntifs.h"
#include "tdi.h"
#include "tdikrnl.h"
#include "tdiinfo.h"

#include "socket.h"
#include "stdio.h"
#include "stdarg.h"
#include "unixwrap.h"

#define BOOL unsigned long
#define TCPIP_DRIVER L"\\Driver\\TcpIp"
#define TCPIP_DEVICE L"\\Device\\Tcp"
#define SMALLBUFFER_SIZE 512 
#define MODULE "**SOCKETS**"

#ifdef DBG
#ifdef NO_SOCKETS_DBGMSG
#undef KDebugPrint
#define KDebugPrint(DbgLevel,_x)
#endif
#endif

#define DEBUG_LEVEL 1
LARGE_INTEGER SockTimeout = {1000,100};
PLARGE_INTEGER pSockTimeout = &SockTimeout;
#define pSockTimeout NULL


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

/************************************************************************/
// BOOL KSocketInitialize()
//
// Initialize kernelsockets library
//
/************************************************************************/
BOOL KSocketInitialize()
{
	//SockTimeout.QuadPart= RELATIVE(MINUTES(10));
    ExInitializePagedLookasideList(&LookasideSocketMem, NULL, NULL, 0, 1024, 'lskN', 0);
    ExInitializePagedLookasideList(&LookasideSocket,NULL,NULL,0,sizeof (KSOCKET),'cosN',0);
    
#ifdef REUSE_SOCKETSIRP
    // check for tcpdevice
    if (!TcpIpDevice)
        return TRUE;
    
    // allocate the single irp we use throughout the sockets library
    SocketsIrp = IoAllocateIrp(TcpIpDevice->StackSize + 1, FALSE);
    if (!SocketsIrp)
        return FALSE;
#endif
    return TRUE;
}

/************************************************************************/
// PVOID KSocketAllocatePool(VOID)
//
// Allocate memory from sockets lookaside                                                                     
//
/************************************************************************/
PVOID KSocketAllocatePool(VOID)
{
    PCHAR    p    = NULL;

    p = ExAllocateFromPagedLookasideList(&LookasideSocketMem);
    if (p)
        memset(p, 0, SMALLBUFFER_SIZE);
    return p;
}

/************************************************************************/
// void KSocketFreePool(PVOID pBuffer)
//
// Free memory to sockets lookaside                                                                     
//
/************************************************************************/
void KSocketFreePool(PVOID pBuffer)
{
    ExFreeToPagedLookasideList(&LookasideSocketMem, pBuffer);
}

/************************************************************************/
// NTSTATUS KSocketCloseObject(HANDLE Handle, PFILE_OBJECT FileObject)
//
// Release a socket object
//
/************************************************************************/
NTSTATUS KSocketCloseObject(HANDLE Handle, PFILE_OBJECT FileObject)
{
    NTSTATUS    Status    = STATUS_SUCCESS;
    
    // dereference referenced object (called for connection and address)
    if (FileObject)
        ObDereferenceObject(FileObject);
    
    // close socket
    if (Handle)
        Status = ZwClose(Handle);
    
    return Status;
}

/************************************************************************/
// PFILE_FULL_EA_INFORMATION KSocketBuildEaValues(PVOID EaName, ULONG NameLength, PVOID EaValue,
//    ULONG ValueLength, PULONG EaLength)
//
// Build EA information for the socket object
//
/************************************************************************/
PFILE_FULL_EA_INFORMATION KSocketBuildEaValues(PVOID EaName, ULONG NameLength, PVOID EaValue,
    ULONG ValueLength, PULONG EaLength)
{
    PFILE_FULL_EA_INFORMATION    Ea;

    *EaLength = FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName[0]) + NameLength + 1 + ValueLength;

    // allocate ea buffer
    Ea = ExAllocatePool(PagedPool, *EaLength);
    if (!Ea)
        return NULL;

    // fill buffer with EA values requested
    Ea->NextEntryOffset = 0;
    Ea->Flags = 0;
    Ea->EaNameLength = (UCHAR) NameLength;
    Ea->EaValueLength = (USHORT) ValueLength;
    memcpy (Ea->EaName,EaName,Ea->EaNameLength + 1);
    if (EaValue && EaLength)
        memcpy (&Ea->EaName[NameLength + 1],EaValue,ValueLength);
    
    return Ea;
}

/************************************************************************/
// NTSTATUS KSocketOpenAddress(PHANDLE Handle, PFILE_OBJECT* FileObject, PVOID Context)
//
// Open address                                                                    
//
/************************************************************************/
NTSTATUS KSocketOpenAddress(PHANDLE Handle, PFILE_OBJECT* FileObject, PVOID Context)
{
    UNICODE_STRING                Name;
    OBJECT_ATTRIBUTES            ObjectAttributes;
    PFILE_FULL_EA_INFORMATION    Ea    = NULL;
    ULONG                        EaLength;
    IO_STATUS_BLOCK                Iosb;
    NTSTATUS                    Status;
    TA_IP_ADDRESS                Sin;

    // initialize address
    Sin.TAAddressCount = 1;
    Sin.Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP;
    Sin.Address[0].AddressType = TDI_ADDRESS_TYPE_IP;
    Sin.Address[0].Address[0].sin_port = 0; // INADDR_ANY;
    Sin.Address[0].Address[0].in_addr = 0;

    // get EA values for address
    Ea = KSocketBuildEaValues(TdiTransportAddress, TDI_TRANSPORT_ADDRESS_LENGTH, &Sin,
            sizeof(TA_IP_ADDRESS), &EaLength);
    if (!Ea)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto __exit;
    }

    // open tcp device
    RtlInitUnicodeString(&Name, TCPIP_DEVICE);
    InitializeObjectAttributes(&ObjectAttributes, &Name, OBJ_CASE_INSENSITIVE, NULL, 0);
    Status = ZwCreateFile(Handle, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &ObjectAttributes, &Iosb, 0,
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,FILE_OPEN_IF,0, Ea, EaLength);
    if (!NT_SUCCESS(Status))
        goto __exit;
    
    Status = ObReferenceObjectByHandle(*Handle, FILE_ANY_ACCESS, 0, KernelMode, FileObject, NULL);

__exit:
    if (Ea)
        ExFreePool(Ea);

    return Status;
}

/************************************************************************/
// NTSTATUS KSocketOpenLocalAddress(PHANDLE Handle, PFILE_OBJECT* FileObject, PVOID Context, USHORT sin_port, ULONG  in_addr)
//
// Open address                                                                    
//
/************************************************************************/
NTSTATUS KSocketOpenLocalAddress(PHANDLE Handle, PFILE_OBJECT* FileObject, PVOID Context, USHORT sin_port, ULONG  in_addr)
{
    UNICODE_STRING                Name;
    OBJECT_ATTRIBUTES            ObjectAttributes;
    PFILE_FULL_EA_INFORMATION    Ea    = NULL;
    ULONG                        EaLength;
    IO_STATUS_BLOCK                Iosb;
    NTSTATUS                    Status;
    TA_IP_ADDRESS                Sin;

    // initialize address
    Sin.TAAddressCount = 1;
    Sin.Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP;
    Sin.Address[0].AddressType = TDI_ADDRESS_TYPE_IP;
    Sin.Address[0].Address[0].sin_port = sin_port; 
    Sin.Address[0].Address[0].in_addr = in_addr;

    // get EA values for address
    Ea = KSocketBuildEaValues(TdiTransportAddress, TDI_TRANSPORT_ADDRESS_LENGTH, &Sin,
            sizeof(TA_IP_ADDRESS), &EaLength);
    if (!Ea)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto __exit;
    }

    // open tcp device
    RtlInitUnicodeString(&Name, TCPIP_DEVICE);
    InitializeObjectAttributes(&ObjectAttributes, &Name, OBJ_CASE_INSENSITIVE, NULL, 0);
    Status = ZwCreateFile(Handle, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &ObjectAttributes, &Iosb, 0,
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,FILE_OPEN_IF,0, Ea, EaLength);
    if (!NT_SUCCESS(Status))
        goto __exit;
    
    Status = ObReferenceObjectByHandle(*Handle, FILE_ANY_ACCESS, 0, KernelMode, FileObject, NULL);

__exit:
    if (Ea)
        ExFreePool(Ea);

    return Status;
}

/************************************************************************/
// NTSTATUS KSocketOpenConnection(PHANDLE Handle, PFILE_OBJECT* FileObject, PVOID Context)
//
// open connection                                                                    
//
/************************************************************************/
NTSTATUS KSocketOpenConnection(PHANDLE Handle, PFILE_OBJECT* FileObject, PVOID Context)
{
    UNICODE_STRING                Name;
    OBJECT_ATTRIBUTES            ObjectAttributes;
    PFILE_FULL_EA_INFORMATION    Ea    = NULL;
    ULONG                        EaLength;
    IO_STATUS_BLOCK                Iosb;
    NTSTATUS                    Status;

    // get EA values for connection
    Ea = KSocketBuildEaValues(TdiConnectionContext, TDI_CONNECTION_CONTEXT_LENGTH, &Context,
            sizeof(PKSOCKET), &EaLength);
    if (!Ea)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto __exit;
    }

    // open tcp device
    RtlInitUnicodeString(&Name, TCPIP_DEVICE);
    InitializeObjectAttributes(&ObjectAttributes, &Name, OBJ_CASE_INSENSITIVE, NULL, 0);
    Status = ZwCreateFile(Handle, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &ObjectAttributes, &Iosb, 0,
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,FILE_OPEN_IF, 0, Ea, EaLength);
    if (!NT_SUCCESS(Status))
        goto __exit;

    Status = ObReferenceObjectByHandle(*Handle, FILE_ANY_ACCESS, 0, KernelMode, FileObject, NULL);

__exit:
    if (Ea)
        ExFreePool(Ea);

    return Status;
}

//************************************************************************
// NTSTATUS KSocketComplete(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)                                                                     
//  
// Socket completion routine
//************************************************************************/
NTSTATUS KSocketComplete(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
{
    PMDL mdl = NULL;
    PMDL nextMdl = NULL;
    PKSOCKET_CTX Ctx = (PKSOCKET_CTX)Context;
    
    // set status block
    Ctx->Iosb.Status = Irp->IoStatus.Status;
    Ctx->Iosb.Information = Irp->IoStatus.Information;
    
    // Free any associated MDL.
    if (Irp->MdlAddress != NULL)
    {
        for (mdl = Irp->MdlAddress; mdl != NULL; mdl = nextMdl)
        {
            nextMdl = mdl->Next;
            MmUnlockPages(mdl);
            
            // This function will also unmap pages.
            IoFreeMdl(mdl);
        }

        // set mdl address to null, to prevent iofreeirp to attempt to free it again
        Irp->MdlAddress = NULL;
    }
        
#ifdef REUSE_SOCKETSIRP
    // set irp for reuse
    IoReuseIrp (Irp,STATUS_SUCCESS);
#else
    // free irp
    IoFreeIrp (Irp);
#endif
    // set event
    if (Ctx)
        KeSetEvent (&Ctx->Event,IO_NO_INCREMENT,FALSE);
    
    return STATUS_MORE_PROCESSING_REQUIRED;
}

//************************************************************************
// NTSTATUS KSocketAssociateAddress(HANDLE Address, PFILE_OBJECT Connection)                                                                     
//  
// Associate address
//************************************************************************/
NTSTATUS KSocketAssociateAddress(HANDLE Address, PFILE_OBJECT Connection)
{
    PDEVICE_OBJECT    DeviceObject;
    PIRP            Irp = NULL;
    NTSTATUS        Status = STATUS_TIMEOUT;
    KSOCKET_CTX        Ctx;
    
    // initialize event and device
    KeInitializeEvent(&Ctx.Event, NotificationEvent, FALSE);    
    DeviceObject = TcpIpDevice;
    
    // allocate TDI_ASSOCIATE_ADDRESS irp
#ifdef REUSE_SOCKETSIRP
    Irp = SocketsIrp;
#else
    Irp = IoAllocateIrp(DeviceObject->StackSize + 1, FALSE);
#endif
    if (!Irp)
        return STATUS_INSUFFICIENT_RESOURCES;
    
    // build irp (this set completion routine too)
    TdiBuildAssociateAddress(Irp, DeviceObject, Connection,KSocketComplete, &Ctx, Address);
    
    // call tcpip
    Status = IoCallDriver(DeviceObject, Irp);
    if (Status == STATUS_PENDING)
    {
        // returned status pending
        Status = KeWaitForSingleObject(&Ctx.Event, Executive, KernelMode, FALSE, pSockTimeout);
        if (Status == STATUS_TIMEOUT)
        {
            KDebugPrint (1, ("%s ***************** KSocketAssociateAddress timeout occurred ***************** cancelling IRP\n", MODULE));
                
            // cancel irp
            IoCancelIrp(Irp);
            
            // wait for completion routine to be called
            KeWaitForSingleObject(&Ctx.Event, Executive, KernelMode, FALSE, NULL);

            Status = STATUS_CONNECTION_ABORTED;
        }
        else
        {
            // ok
            Status = Ctx.Iosb.Status;
        }    
    }

    return Status;
}

//************************************************************************
// NTSTATUS KSocketConnect(PKSOCKET pSocket, ULONG Address, USHORT Port)
//  
// Connect socket to address:port                                                                   
//************************************************************************/
NTSTATUS KSocketConnect(PKSOCKET pSocket, ULONG Address, USHORT Port)
{
    PDEVICE_OBJECT        DeviceObject;
    PIRP                Irp = NULL;
    NTSTATUS            Status = STATUS_TIMEOUT;
    KSOCKET_CTX            Ctx;
    TDI_CONNECTION_INFORMATION    RequestInfo;
    TA_IP_ADDRESS            RemoteAddress;
    PFILE_OBJECT            Connection;
    
    KDebugPrint (2,("%s KSocketConnect called.\n",MODULE));

    if (!pSocket)
        return STATUS_UNSUCCESSFUL;
    
    // set parameters
    Connection = pSocket->ConnectionFile;
    memset (&RequestInfo,0, sizeof(TDI_CONNECTION_INFORMATION));
    memset (&RemoteAddress,0,sizeof (TA_IP_ADDRESS));
    
    RemoteAddress.TAAddressCount = 1;
    RemoteAddress.Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP;
    RemoteAddress.Address[0].AddressType = TDI_ADDRESS_TYPE_IP;
    RemoteAddress.Address[0].Address[0].sin_port = Port;
    RemoteAddress.Address[0].Address[0].in_addr = Address;
    
    RequestInfo.UserDataLength = 0;
    RequestInfo.UserData = NULL;
    RequestInfo.OptionsLength = 0;
    RequestInfo.Options = NULL;
    RequestInfo.RemoteAddressLength = sizeof(TA_IP_ADDRESS);
    RequestInfo.RemoteAddress = &RemoteAddress;
    
    // initialize event and device
    KeInitializeEvent(&Ctx.Event, NotificationEvent, FALSE);    
    DeviceObject = TcpIpDevice;
    
    // allocate TDI_CONNECT irp
#ifdef REUSE_SOCKETSIRP
    Irp = SocketsIrp;
#else
    Irp = IoAllocateIrp(DeviceObject->StackSize + 1, FALSE);
#endif
    
    // build irp (this set completion routine too)
    TdiBuildConnect (Irp, DeviceObject,Connection,KSocketComplete, &Ctx,NULL, &RequestInfo,&RequestInfo);
    
    // call tcpip
    Status = IoCallDriver(DeviceObject, Irp);
    if (Status == STATUS_PENDING)
    {
        // returned status pending
        Status = KeWaitForSingleObject(&Ctx.Event, Executive, KernelMode, FALSE, 0);//&SockTimeout);
        if (Status == STATUS_TIMEOUT)
        {
            KDebugPrint (1, ("%s ***************** KSocketConnect timeout occurred ***************** cancelling IRP\n", MODULE));
                
            // cancel irp
            IoCancelIrp(Irp);
            
            // wait for completion routine to be called
            KeWaitForSingleObject(&Ctx.Event, Executive, KernelMode, FALSE, NULL);

            Status = STATUS_CONNECTION_ABORTED;
        }
        else
            // ok
            Status = Ctx.Iosb.Status;
    }
    
    if (Status == STATUS_SUCCESS)
        pSocket->Connected = TRUE;
    
       return Status;
}

//************************************************************************
// NTSTATUS KSocketListen(PKSOCKET pSocket)
//  
// Sets the socket to listening mode                                                                   
//************************************************************************/
NTSTATUS KSocketListen(PKSOCKET pSocket)
{
    PDEVICE_OBJECT        DeviceObject;
    PIRP                Irp = NULL;
    NTSTATUS            Status = STATUS_TIMEOUT;
    KSOCKET_CTX            Ctx;
    TDI_CONNECTION_INFORMATION    RequestInfo;
    TDI_CONNECTION_INFORMATION    ReturnInfo;
    PFILE_OBJECT            Connection;
    
    KDebugPrint (2,("%s KSocketConnect called.\n",MODULE));

    if (!pSocket)
        return STATUS_UNSUCCESSFUL;
    
    // set parameters
    Connection = pSocket->ConnectionFile;
    memset (&RequestInfo,0, sizeof(TDI_CONNECTION_INFORMATION));
	memset (&ReturnInfo,0, sizeof(TDI_CONNECTION_INFORMATION));



    RequestInfo.UserData            = NULL;
	RequestInfo.UserDataLength      = 0;
	RequestInfo.Options             = 0;
	RequestInfo.OptionsLength       = sizeof(ULONG);
	RequestInfo.RemoteAddress       = NULL;        
	RequestInfo.RemoteAddressLength = 0;

    ReturnInfo.UserData            = NULL;
	ReturnInfo.UserDataLength      = 0;
	ReturnInfo.Options             = 0;
	ReturnInfo.OptionsLength       = sizeof(ULONG);
	ReturnInfo.RemoteAddress       = 
        (PTA_IP_ADDRESS)ExAllocatePool(NonPagedPool,sizeof(TA_IP_ADDRESS));
	ReturnInfo.RemoteAddressLength = sizeof(TA_IP_ADDRESS);
    
    // initialize event and device
    KeInitializeEvent(&Ctx.Event, NotificationEvent, FALSE);    
    DeviceObject = TcpIpDevice;
    
    // allocate TDI_CONNECT irp
#ifdef REUSE_SOCKETSIRP
    Irp = SocketsIrp;
#else
    Irp = IoAllocateIrp(DeviceObject->StackSize + 1, FALSE);
#endif
    
    // build irp (this set completion routine too)
    TdiBuildListen(Irp, DeviceObject,Connection,KSocketComplete, &Ctx, 0, &RequestInfo,&ReturnInfo);
    
    // call tcpip
    Status = IoCallDriver(DeviceObject, Irp);
    if (Status == STATUS_PENDING)
    {
        // returned status pending
        Status = KeWaitForSingleObject(&Ctx.Event, Executive, KernelMode, FALSE, 0);//&SockTimeout);
        if (Status == STATUS_TIMEOUT)
        {
            KDebugPrint (1, ("%s ***************** KSocketListen timeout occurred ***************** cancelling IRP\n", MODULE));
                
            // cancel irp
            IoCancelIrp(Irp);
            
            // wait for completion routine to be called
            KeWaitForSingleObject(&Ctx.Event, Executive, KernelMode, FALSE, NULL);

            Status = STATUS_CONNECTION_ABORTED;
        }
        else
            // ok
            Status = Ctx.Iosb.Status;
    }
    
    if (Status == STATUS_SUCCESS)
        pSocket->Connected = TRUE;
    
       return Status;
}

//************************************************************************
// NTSTATUS KSocketDisconnect(PKSOCKET pSocket
//  
// Disconnect socket                                                                   
//************************************************************************/
NTSTATUS KSocketDisconnect(PKSOCKET pSocket)
{
    PDEVICE_OBJECT    DeviceObject;
    PIRP            Irp = NULL;
    NTSTATUS        Status = STATUS_TIMEOUT;
    TDI_CONNECTION_INFORMATION    ReqDisconnect;
    PFILE_OBJECT    Connection;
    ULONG Flags;
    KSOCKET_CTX    Ctx;
    
    // check if socket is already disconnected
    if (!pSocket)
        return STATUS_UNSUCCESSFUL;
    
    if (!pSocket->Connected)
        return STATUS_ALREADY_DISCONNECTED;
    
    // set parameters
    Connection = pSocket->ConnectionFile;
    memset(&ReqDisconnect,0,sizeof (TDI_CONNECTION_INFORMATION));
    Flags = TDI_DISCONNECT_ABORT;

       // initialize event and device
    KeInitializeEvent(&Ctx.Event, NotificationEvent, FALSE);    
    DeviceObject = TcpIpDevice;
        
    // allocate TDI_DISCONNECT irp
#ifdef REUSE_SOCKETSIRP
    Irp = SocketsIrp;
#else
    Irp = IoAllocateIrp(DeviceObject->StackSize + 1, FALSE);
#endif
    if (!Irp)
        return STATUS_INSUFFICIENT_RESOURCES;
    
    // build irp (this set completion routine too)
    TdiBuildDisconnect (Irp, DeviceObject,Connection,KSocketComplete, &Ctx, NULL,Flags,&ReqDisconnect,&ReqDisconnect);
    
    // call tcpip
    Status = IoCallDriver(DeviceObject, Irp);
    if (Status == STATUS_PENDING)
    {
        // returned status pending
        Status = KeWaitForSingleObject(&Ctx.Event, Executive, KernelMode, FALSE, pSockTimeout);
        if (Status == STATUS_TIMEOUT)
        {
            KDebugPrint (1, ("%s ***************** KSocketDisconnect timeout occurred ***************** cancelling IRP\n", MODULE));
                    
            // cancel irp
            IoCancelIrp(Irp);
                
            // wait for completion routine to be called
            KeWaitForSingleObject(&Ctx.Event, Executive, KernelMode, FALSE, NULL);

            Status = STATUS_CONNECTION_ABORTED;
        }
        else
        {
            // ok
            Status = Ctx.Iosb.Status;
        }    
    }
    
    if (NT_SUCCESS (Status))
        pSocket->Connected = FALSE;
    
    return Status;
}

//************************************************************************
// NTSTATUS KSocketSend(PKSOCKET pSocket, PVOID Buffer, SIZE_T Size, PSIZE_T BytesSent)
//  
// Send buffer thru socket                                                                   
//************************************************************************/
NTSTATUS KSocketSend(PKSOCKET pSocket, PVOID Buffer, SIZE_T Size, PSIZE_T BytesSent)
{
    PDEVICE_OBJECT    DeviceObject;
    PFILE_OBJECT    Connection;
    PIRP            Irp = NULL;
    NTSTATUS        Status = STATUS_TIMEOUT;
    KSOCKET_CTX Ctx;
    PMDL            Mdl;
    
    KDebugPrint (2,("%s KSocketSend called.\n",MODULE));
    
    if (!pSocket)
        return STATUS_UNSUCCESSFUL;

    // set parameters
    Connection = pSocket->ConnectionFile;
    *BytesSent = 0;
    
    // initialize event and device
    KeInitializeEvent(&Ctx.Event, NotificationEvent, FALSE);    
    DeviceObject = TcpIpDevice;
            
    // allocate TDI_SEND irp
#ifdef REUSE_SOCKETSIRP
    Irp = SocketsIrp;
#else
    Irp = IoAllocateIrp(DeviceObject->StackSize + 1, FALSE);
#endif
    if (!Irp)
        return STATUS_INSUFFICIENT_RESOURCES;
    
    // build mdl
    Mdl = IoAllocateMdl(Buffer, Size, FALSE, FALSE, NULL);
    if (!Mdl)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        IoFreeIrp (Irp);
        return Status;
    }
    
    __try
    {
        MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        IoFreeMdl (Mdl);
        IoFreeIrp (Irp);
        Status = STATUS_UNSUCCESSFUL;
        return Status;
    }
    Mdl->Next = NULL;
    
    // build irp (this set completion routine too)
    TdiBuildSend (Irp, DeviceObject,Connection,KSocketComplete, &Ctx,Mdl,0,Size);
    
    // call tcp
    Status = IoCallDriver(DeviceObject, Irp);
    if (Status == STATUS_PENDING)
    {
        // returned status pending
        Status = KeWaitForSingleObject(&Ctx.Event, Executive, KernelMode, FALSE, pSockTimeout);
        if (Status == STATUS_TIMEOUT)
        {
               KDebugPrint (1, ("%s ***************** KSocketSend timeout occurred ***************** cancelling IRP\n", MODULE));
                    
            // cancel irp
            IoCancelIrp(Irp);
                    
            // wait for completion routine to be called
            KeWaitForSingleObject(&Ctx.Event, Executive, KernelMode, FALSE, NULL);
            Status = STATUS_CONNECTION_ABORTED;
        }
        else
        {
            // ok
            Status = Ctx.Iosb.Status;
        }
    }
    
    // return sent bytes
    *BytesSent = Ctx.Iosb.Information;
    
    // check transferred bytes
    if (Ctx.Iosb.Information != Size)
        Status = STATUS_CONNECTION_ABORTED;

    if (!NT_SUCCESS(Status))
    {
        KDebugPrint(1, ("%s KSocketSend returned error %08x (ReqSent:%d,OkSent:%d)\n", MODULE, Status,
            Size, *BytesSent));
    }
    
    return Status;
}

//************************************************************************
// NTSTATUS KSocketReceive(PKSOCKET pSocket, PVOID Buffer, SIZE_T Size, PSIZE_T BytesReceived, BOOLEAN ReceivePeek)
//  
// Receive buffer thru socket                                                                   
//************************************************************************/
NTSTATUS KSocketReceive(PKSOCKET pSocket, PVOID Buffer, SIZE_T Size, PSIZE_T BytesReceived, BOOLEAN ReceivePeek)
{
    PDEVICE_OBJECT    DeviceObject;
    PFILE_OBJECT    Connection;
    PIRP            Irp = NULL;
    NTSTATUS        Status = STATUS_TIMEOUT;
    PMDL            Mdl;
    ULONG            Flags;
    KSOCKET_CTX        Ctx;
        
    KDebugPrint (2,("%s KSocketReceive called.\n",MODULE));
    
    if (!pSocket)
        return STATUS_UNSUCCESSFUL;
    
    // set parameters
    Connection = pSocket->ConnectionFile;
    *BytesReceived = 0;
    
    if (ReceivePeek)
        Flags = TDI_RECEIVE_PEEK;
    else
        Flags = TDI_RECEIVE_NORMAL;
    
    // initialize event and device
    KeInitializeEvent(&Ctx.Event, NotificationEvent, FALSE);    
    DeviceObject = TcpIpDevice;
                
    // allocate TDI_RECEIVE irp
#ifdef REUSE_SOCKETSIRP
    Irp = SocketsIrp;
#else
    Irp = IoAllocateIrp(DeviceObject->StackSize + 1, FALSE);
#endif
    if (!Irp)
        return STATUS_INSUFFICIENT_RESOURCES;
    
    // build mdl
    Mdl = IoAllocateMdl(Buffer, Size, FALSE, FALSE, NULL);
    if (!Mdl)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        IoFreeIrp (Irp);
        return Status;
    }
    
    __try
    {
        MmProbeAndLockPages(Mdl, KernelMode, IoWriteAccess);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        IoFreeMdl (Mdl);
        IoFreeIrp (Irp);
        Status = STATUS_UNSUCCESSFUL;
        return Status;
    }
    Mdl->Next = NULL;
    
    // build irp (this set completion routine too)
    TdiBuildReceive (Irp, DeviceObject,Connection,KSocketComplete, &Ctx,Mdl,Flags,Size);
    
    // call tcp
    Status = IoCallDriver(DeviceObject, Irp);
    if (Status == STATUS_PENDING)
    {
        // returned status pending
        Status = KeWaitForSingleObject(&Ctx.Event, Executive, KernelMode, FALSE, pSockTimeout);
        if (Status == STATUS_TIMEOUT)
        {
            KDebugPrint (1, ("%s ***************** KSocketReceive timeout occurred ***************** cancelling IRP\n", MODULE));
                    
            // cancel irp
            IoCancelIrp(Irp);
                    
            // wait for completion routine to be called
            KeWaitForSingleObject(&Ctx.Event, Executive, KernelMode, FALSE, NULL);

            Status = STATUS_CONNECTION_ABORTED;
        }
        else
        {
            // ok
            Status = Ctx.Iosb.Status;
        }
    }
    
    // return received bytes
    *BytesReceived = Ctx.Iosb.Information;
    
    // check received bytes
    if (Ctx.Iosb.Information == 0)
        Status = STATUS_CONNECTION_ABORTED;

    if (!NT_SUCCESS(Status))
    {
        KDebugPrint(1, ("%s KSocketReceive returned error %08x (ReqRecv:%d,OkRecv:%d)\n", MODULE, Status,
            Size, *BytesReceived));
    }
    
    return Status;
}

//************************************************************************
// VOID KSocketClose(PKSOCKET Socket)                                                                     
//  
// Close socket and Release socket memory                                                                   
//************************************************************************/
VOID KSocketClose(PKSOCKET Socket)
{
    if (Socket == NULL)
    {
        return;
    }

    KSocketCloseObject(Socket->TransportAddressHandle, Socket->TransportAddress);
    KSocketCloseObject(Socket->ConnectionFileHandle, Socket->ConnectionFile);

    ExFreeToPagedLookasideList (&LookasideSocket,Socket);

    Socket = NULL;
}

//************************************************************************
// NTSTATUS KSocketCreate(OUT PKSOCKET* Socket)                                                                     
//  
// Create socket                                                                   
//************************************************************************/
NTSTATUS KSocketCreate(OUT PKSOCKET* Socket)
{
    NTSTATUS    Status    = STATUS_SUCCESS;
    PKSOCKET    iSocket    = NULL;

#ifdef ALWAYS_DISABLESOCKETS
    KDebugPrint(1,("%s Sockets disabled, connect skipped.\n", MODULE));
    return STATUS_UNSUCCESSFUL;
#endif
    
    // check disabled sockets
    if (DisableSockets)
    {
        KDebugPrint(1,("%s Sockets disabled, connect skipped.\n", MODULE));
        return STATUS_UNSUCCESSFUL;
    }
    
    // handle KAV (crash if not patched)
    //ModulePatchKAV();

    // allocate memory for a new socket
    iSocket = ExAllocateFromPagedLookasideList(&LookasideSocket);
    if (!iSocket)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto __exit;
    }
    memset (iSocket,0, sizeof(KSOCKET));

    // open transport address
    Status = KSocketOpenAddress(&iSocket->TransportAddressHandle, &iSocket->TransportAddress,
        iSocket);
    if (!NT_SUCCESS(Status))
        goto __exit;

    // create connection endpoint
    Status = KSocketOpenConnection(&iSocket->ConnectionFileHandle, &iSocket->ConnectionFile,
                iSocket);
    if (!NT_SUCCESS(Status))
        goto __exit;

    // associate address with connection
    Status = KSocketAssociateAddress(iSocket->TransportAddressHandle, iSocket->ConnectionFile);
    if (!NT_SUCCESS(Status))
        goto __exit;
    
__exit:
    if (!NT_SUCCESS(Status))
    {
        if (iSocket)
            KSocketClose(iSocket);
        *Socket = NULL;
    }
    else
        *Socket = iSocket;

    return Status;
}

//************************************************************************
// NTSTATUS KSocketCreateAndBind(OUT PKSOCKET* Socket, IN USHORT sin_port, IN ULONG  in_addr)                                                                     
//  
// Create socket and binds it to the specified address                                                                   
//************************************************************************/
NTSTATUS KSocketCreateAndBind(OUT PKSOCKET* Socket, IN USHORT sin_port, IN ULONG  in_addr)
{
    NTSTATUS    Status    = STATUS_SUCCESS;
    PKSOCKET    iSocket    = NULL;

#ifdef ALWAYS_DISABLESOCKETS
    KDebugPrint(1,("%s Sockets disabled, connect skipped.\n", MODULE));
    return STATUS_UNSUCCESSFUL;
#endif
    
    // check disabled sockets
    if (DisableSockets)
    {
        KDebugPrint(1,("%s Sockets disabled, connect skipped.\n", MODULE));
        return STATUS_UNSUCCESSFUL;
    }
    
    // handle KAV (crash if not patched)
    //ModulePatchKAV();

    // allocate memory for a new socket
    iSocket = ExAllocateFromPagedLookasideList(&LookasideSocket);
    if (!iSocket)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto __exit;
    }
    memset (iSocket,0, sizeof(KSOCKET));

    // open transport address
    Status = KSocketOpenLocalAddress(&iSocket->TransportAddressHandle, &iSocket->TransportAddress,
        iSocket, sin_port, in_addr);
    if (!NT_SUCCESS(Status))
        goto __exit;

    // create connection endpoint
    Status = KSocketOpenConnection(&iSocket->ConnectionFileHandle, &iSocket->ConnectionFile,
                iSocket);
    if (!NT_SUCCESS(Status))
        goto __exit;

    // associate address with connection
    Status = KSocketAssociateAddress(iSocket->TransportAddressHandle, iSocket->ConnectionFile);
    if (!NT_SUCCESS(Status))
        goto __exit;
    
__exit:
    if (!NT_SUCCESS(Status))
    {
        if (iSocket)
            KSocketClose(iSocket);
        *Socket = NULL;
    }
    else
        *Socket = iSocket;

    return Status;
}


/************************************************************************/
// NTSTATUS KSocketReadLine(PKSOCKET pSocket, PCHAR buf, SIZE_T maxlen, PSIZE_T ReceivedBytes)
//
// Read line (ascii) from network
//
/************************************************************************/
NTSTATUS KSocketReadLine(PKSOCKET pSocket, PCHAR buf, SIZE_T maxlen, PSIZE_T ReceivedBytes)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    UCHAR c = 0;
    ULONG i = 0;
    ULONG received = 0;

    // check params
    if (!pSocket || !buf || !ReceivedBytes || !maxlen)
        goto __exit;
    
    *ReceivedBytes = 0;
    if (!pSocket->Connected)
        goto __exit;
    
    // read line char by char, and stop at EOL
    memset (buf, 0, maxlen);
    while (TRUE)
    {
        if (i == maxlen)
            break;
        
        // get char from socket
        Status = KSocketReceive (pSocket,&c,1,&received,FALSE);
        if (!NT_SUCCESS (Status) || received == 0)
            break;
        
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
    // treat 0 size received as error
    if (received == 0)
        Status = STATUS_NO_DATA_DETECTED;
    
    return Status;
}

/************************************************************************/
// NTSTATUS KSocketWriteLine(PKSOCKET pSocket, const char* format, ...)
//
// write formatted line (ascii) to network
//
/************************************************************************/
NTSTATUS KSocketWriteLine(PKSOCKET pSocket, const char* format, ...)
{
    va_list        ap;
    char*        buf;
    ULONG        len;
    NTSTATUS    Status;
    SIZE_T        BytesSent    = 0;

    // allocate memory
    buf = KSocketAllocatePool();
    if (!buf)
        return STATUS_INSUFFICIENT_RESOURCES;

    // build line
    va_start(ap, format);
    _vsnprintf(buf, SMALLBUFFER_SIZE, format, ap);
    va_end(ap);
    len = strlen(buf);
    
    // send
    Status = KSocketSend(pSocket, buf, len, &BytesSent);

    // free buffer
    KSocketFreePool(buf);

    // check if we've sent all bytes
    if (BytesSent < len)
        return STATUS_UNSUCCESSFUL;
    
    return Status;
}




// taken from http://ftp.k-team.com/korebot/libkorebot-doc/kb__wav_8h.html#a1
#define SWAP_LONG(l)  (((l>>24)&0xff)|((l>>8)&0xff00)|\
                        ((l<<8)&0xff0000)|((l<<24)&0xff000000))

unsigned long htonl (IN unsigned long hostlong)

{
    return SWAP_LONG( hostlong );
}

#define SWAP_SHORT(s) ( ( ((s) >> 8) & 0x00FF ) |\
                        ( ((s) << 8) & 0xFF00 ) )

unsigned short htons (IN unsigned short hostshort)
{
    return SWAP_SHORT( hostshort );
}

// BELOW TAKEN FROM http://www.koders.com/c/fid40AA0CED3155749EA254A52A11CE0A926219D892.aspx

#define INADDR_NONE 0

int inet_aton(const char *cp, struct in_addr *addr);

long inet_addr(const char * cp)
{
	struct in_addr val;

	if (inet_aton(cp, &val))
		return (val.s_addr);
	return (INADDR_NONE);
}

/*
 * Check whether "cp" is a valid ascii representation
 * of an Internet address and convert to a binary address.
 * Returns 1 if the address is valid, 0 if not.
 * This replaces inet_addr, the return value from which
 * cannot distinguish between failure and a local broadcast address.
 */

int isasciiBSD ( int ch ) 
{
    return (unsigned int)ch < 128u;
}/*
int isxdigit ( int ch )
{
    return (unsigned int)( ch         - '0') < 10u  || 
           (unsigned int)((ch | 0x20) - 'a') <  6u;
}
int islower( int ch ) {
    return (unsigned int) (ch - 'a') < 26u;
}
int isdigit( int ch ) {
    return (unsigned int)(ch - '0') < 10u;
}
*/

int inet_aton(const char *cp, struct in_addr *addr)
{
	unsigned long val;
	int base, n;
	unsigned char c;
	unsigned int parts[4];
	unsigned int *pp = parts;

	c = *cp;
	for (;;) {
		/*
		 * Collect number up to ``.''.
		 * Values are specified as for C:
		 * 0x=hex, 0=octal, isdigit=decimal.
		 */
#if 0
		if (!isdigit(c))
#else
		if (c != '0' && c != '1' && c != '2' && c != '3' && c != '4' &&
		    c != '5' && c != '6' && c != '7' && c != '8' && c != '9')
#endif
			return (0);
		val = 0; base = 10;
		if (c == '0') {
			c = *++cp;
			if (c == 'x' || c == 'X')
				base = 16, c = *++cp;
			else
				base = 8;
		}
		for (;;) {
			if (isasciiBSD(c) && isdigit(c)) {
				val = (val * base) + (c - '0');
				c = *++cp;
			} else if (base == 16 && isasciiBSD(c) && isxdigit(c)) {
				val = (val << 4) |
					(c + 10 - (islower(c) ? 'a' : 'A'));
				c = *++cp;
			} else
				break;
		}
		if (c == '.') {
			/*
			 * Internet format:
			 *	a.b.c.d
			 *	a.b.c	(with c treated as 16 bits)
			 *	a.b	(with b treated as 24 bits)
			 */
			if (pp >= parts + 3)
				return (0);
			*pp++ = val;
			c = *++cp;
		} else
			break;
	}
	/*
	 * Check for trailing characters.
	 */
	if (c != '\0' && (!isasciiBSD(c) || !isspace(c)))
		return (0);
	/*
	 * Concoct the address according to
	 * the number of parts specified.
	 */
	n = pp - parts + 1;
	switch (n) {

	case 0:
		return (0);		/* initial nondigit */

	case 1:				/* a -- 32 bits */
		break;

	case 2:				/* a.b -- 8.24 bits */
		if (val > 0xffffff)
			return (0);
		val |= parts[0] << 24;
		break;

	case 3:				/* a.b.c -- 8.8.16 bits */
		if (val > 0xffff)
			return (0);
		val |= (parts[0] << 24) | (parts[1] << 16);
		break;

	case 4:				/* a.b.c.d -- 8.8.8.8 bits */
		if (val > 0xff)
			return (0);
		val |= (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8);
		break;
	}
	if (addr)
		addr->s_addr = htonl(val);
	return (1);
}




#endif