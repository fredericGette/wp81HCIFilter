// bcdedit /store f:\EFIESP\efi\Microsoft\Boot\BCD /set {default} bootlog Yes
// bcdedit /store f:\EFIESP\efi\Microsoft\Boot\BCD /set {default} testsigning yes
//
// set PATH=C:\Program Files (x86)\Microsoft Visual Studio 12.0\Common7\IDE\;C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC\bin\x86_arm;C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC\bin;%PATH%
//

#include <ntifs.h>
#include <wdm.h>
#include <ntstrsafe.h>

// https://www.osr.com/nt-insider/2017-issue1/making-device-objects-accessible-safe/

VOID printBufferContent(PVOID buffer, size_t bufSize)
{
	CHAR hexString[256];
	CHAR chrString[256];
	CHAR tempString[8];
	size_t length;
	RtlZeroMemory(hexString, 256);
	RtlZeroMemory(chrString, 256);
	RtlZeroMemory(tempString, 8);
	unsigned char *p = (unsigned char*)buffer;
	unsigned int i = 0;
	BOOLEAN multiLine = FALSE;
	for(; i<bufSize && i < 608; i++)
	{
		RtlStringCbPrintfA(tempString, 8, "%02X ", p[i]);
		RtlStringCbCatA(hexString, 256, tempString);

		RtlStringCbPrintfA(tempString, 8, "%c", p[i]>31 && p[i]<127 ? p[i] : '.' );
		RtlStringCbCatA(chrString, 256, tempString);

		if ((i+1)%38 == 0)
		{
			DbgPrint("Control!%s%s", hexString, chrString);
			RtlZeroMemory(hexString, 256);
			RtlZeroMemory(chrString, 256);
			multiLine = TRUE;
		}
	}
	RtlStringCbLengthA(hexString,256,&length);
	if (length != 0)
	{
		CHAR padding[256];
		RtlZeroMemory(padding, 256);
		if (multiLine)
		{
			RtlStringCbPrintfA(padding, 256, "%*s", 3*(38-(i%38)),"");
		}

		DbgPrint("Control!%s%s%s", hexString, padding, chrString);
	}

	if (i == 608)
	{
		DbgPrint("Control!...\n");
	}	
}

void DriverUnload(PDRIVER_OBJECT DriverObject) {
	
	DbgPrint("Control!DriverUnload\n");
	
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\wp81controldevice");
	// delete symbolic link
	IoDeleteSymbolicLink(&symLink);
	// delete device object
	IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS DeviceCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	
	DbgPrint("Control!DeviceCreate\n");
	
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	
	return STATUS_SUCCESS;
}

NTSTATUS DeviceClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	
	DbgPrint("Control!DeviceClose\n");
	
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	
	return STATUS_SUCCESS;
}

NTSTATUS CompleteIrp(PIRP Irp, NTSTATUS status, ULONG_PTR info) {
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

VOID SendAnIoctl(PDEVICE_OBJECT TargetDevice, ULONG IoControlCode, PVOID pOutputBuffer, size_t OutputBufferLength)
{
    NTSTATUS        status;
    KEVENT          event;
    IO_STATUS_BLOCK iosb;
    PIRP            irp;
	//PVOID			pOutputBuffer;
    
	DbgPrint("Control!SendAnIoctl TargetDevice=0x%p IoControlCode=0x%X pOutputBuffer=0x%p OutputBufferLength=0x%X\n",TargetDevice, IoControlCode, pOutputBuffer, OutputBufferLength);

	//pOutputBuffer = ExAllocatePoolWithTag(PagedPool, 4, 'wp81');	

    irp = IoBuildDeviceIoControlRequest(IoControlCode,
                                        TargetDevice,
                                        NULL,
                                        0,
                                        pOutputBuffer,
                                        OutputBufferLength,
                                        FALSE,
                                        &event,
                                        &iosb);
 
    if (irp == NULL) {
        goto Exit;
    }
 
    status = IoCallDriver(TargetDevice, irp);
 
    if (status == STATUS_PENDING) {
		DbgPrint("Control! Wait STATUS_PENDING\n");

        KeWaitForSingleObject(&event, 
                              Executive,
                              KernelMode,
                              FALSE,
                              NULL);
        status = iosb.Status;
    }

	printBufferContent(pOutputBuffer, 4);
 
Exit:
	//ExFreePoolWithTag(pOutputBuffer, 'wp81');
	DbgPrint("Control!End SendAnIoctl\n");
    return;
}

NTSTATUS queryFilterDeviceObject(PDEVICE_OBJECT *pFilterDeviceObject)
{
	NTSTATUS status;
	HANDLE hRegister;
	ULONG ulSize;
	PKEY_VALUE_PARTIAL_INFORMATION info;
	ULONG filterDeviceObjectAddr;
	OBJECT_ATTRIBUTES objectAttributes;
	UNICODE_STRING usKeyName;
	UNICODE_STRING usValueName;
	RtlInitUnicodeString(&usKeyName, L"\\REGISTRY\\MACHINE\\System\\CurrentControlSet\\Enum\\SystemBusQc\\SMD_BT\\4&315a27b&0&4097\\Device Parameters");
	RtlInitUnicodeString(&usValueName, L"wp81DeviceObjectPointer");
	InitializeObjectAttributes(&objectAttributes,
	                           &usKeyName,
	                           OBJ_CASE_INSENSITIVE,
	                           NULL,
	                           NULL );
	status = ZwOpenKey(&hRegister, KEY_ALL_ACCESS, &objectAttributes);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Control!InitializeObjectAttributes failed 0x%x\n", status);
	}
	else {
		status = ZwQueryValueKey(hRegister,
	                           &usValueName,
	                           KeyValuePartialInformation ,
	                           NULL,
	                           0,
	                           &ulSize);
		if (status==STATUS_OBJECT_NAME_NOT_FOUND || ulSize==0) {
			DbgPrint("Control!First ZwQueryValueKey failed 0x%x\n", status);
		}
		else {
			DbgPrint("Control!ulSize=0x%X\n", ulSize);
			info = ExAllocatePoolWithTag(PagedPool, ulSize, 'wp81');			
			status = ZwQueryValueKey(hRegister,
	                           &usValueName,
	                           KeyValuePartialInformation ,
	                           info,
	                           ulSize,
	                           &ulSize);
			if (!NT_SUCCESS(status)) {
				DbgPrint("Control!Second ZwQueryValueKey failed 0x%x\n", status);
			}
			else
			{
				DbgPrint("Control!info->Type=0x%X info->DataLength=0x%X\n", info->Type, info->DataLength);

				RtlMoveMemory(&filterDeviceObjectAddr, info->Data, info->DataLength);
				DbgPrint("Control!filterDeviceObjectAddr=0x%X\n", filterDeviceObjectAddr);
				*pFilterDeviceObject = (PDEVICE_OBJECT)filterDeviceObjectAddr;
			}
			ExFreePoolWithTag(info, 'wp81');
		}
		ZwClose(hRegister);
	}

	return status;
}

NTSTATUS DriverDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	NTSTATUS status;
	PDEVICE_OBJECT pFilterDeviceObject;
	ULONG IoControlCode;
	size_t InputBufferLength;
	size_t OutputBufferLength;
	PVOID pOutputBuffer;

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/buffer-descriptions-for-i-o-control-codes#method_neither
	IoControlCode = Irp->Tail.Overlay.CurrentStackLocation->Parameters.DeviceIoControl.IoControlCode;
	InputBufferLength = Irp->Tail.Overlay.CurrentStackLocation->Parameters.DeviceIoControl.InputBufferLength;
	OutputBufferLength = Irp->Tail.Overlay.CurrentStackLocation->Parameters.DeviceIoControl.OutputBufferLength;	

	DbgPrint("Control!DriverDispatch IoControlCode=0x%X InputBufferLength=0x%X OutputBufferLength=0x%X\n",IoControlCode,InputBufferLength,OutputBufferLength);

	pOutputBuffer = Irp->UserBuffer;
	DbgPrint("Control!DriverDispatch pOutputBuffer=0x%p\n", pOutputBuffer);

	status = queryFilterDeviceObject(&pFilterDeviceObject);
	if (NT_SUCCESS(status)) {
		DbgPrint("Control!pFilterDeviceObject=0x%p\n", pFilterDeviceObject);
		DbgPrint("Control!FDO Type=%d (3=Device), Size=%d, Driver=0x%p\n",pFilterDeviceObject->Type, pFilterDeviceObject->Size, pFilterDeviceObject->DriverObject);
		SendAnIoctl(pFilterDeviceObject, IoControlCode, pOutputBuffer, OutputBufferLength);	
	}
	else {
		DbgPrint("Control!queryFilterDeviceObject failed 0x%x\n", status);
	}

	return CompleteIrp(Irp, status, 0);
}

NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	
	UNREFERENCED_PARAMETER(RegistryPath);
	
	DbgPrint("Control!DriverEntry\n");
	
	DriverObject->DriverUnload = DriverUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DeviceCreate;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DeviceClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDispatch;
	
	UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\wp81controldevice");
	
	PDEVICE_OBJECT DeviceObject;
	NTSTATUS status = IoCreateDevice(
		DriverObject, // our driver object
		0, // no need for extra bytes
		&devName, // the device name
		FILE_DEVICE_UNKNOWN, // device type
		0, // characteristics flags
		FALSE, // not exclusive
		&DeviceObject); // the resulting pointer
	if (!NT_SUCCESS(status)) {
		DbgPrint("Control!Failed to create device object (0x%x)\n", status);
		return status;
	}
	
	NT_ASSERT(DeviceObject);
	
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\wp81controldevice");
	status = IoCreateSymbolicLink(&symLink, &devName);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Control!Failed to create symbolic link (0x%x)\n", status);
		IoDeleteDevice(DeviceObject);
		return status;
	}
	NT_ASSERT(NT_SUCCESS(status));
	
	return STATUS_SUCCESS;
}