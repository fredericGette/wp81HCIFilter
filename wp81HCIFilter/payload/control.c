// bcdedit /store f:\EFIESP\efi\Microsoft\Boot\BCD /set {default} bootlog Yes
// bcdedit /store f:\EFIESP\efi\Microsoft\Boot\BCD /set {default} testsigning yes
//
// set PATH=C:\Program Files (x86)\Microsoft Visual Studio 12.0\Common7\IDE\;C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC\bin\x86_arm;C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC\bin;%PATH%
//

#include <ntifs.h>
#include <wdm.h>
#include <ntstrsafe.h>

// https://www.osr.com/nt-insider/2017-issue1/making-device-objects-accessible-safe/

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

VOID SendAnIoctl(PDEVICE_OBJECT TargetDevice)
{
    NTSTATUS        status;
    KEVENT          event;
    IO_STATUS_BLOCK iosb;
    PIRP            irp;
    
	DbgPrint("Control!SendAnIoctl\n");

    irp = IoBuildDeviceIoControlRequest(0x80002000,
                                        TargetDevice,
                                        NULL,
                                        0,
                                        NULL,
                                        0,
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
 
Exit:
	DbgPrint("Control!End SendAnIoctl\n");
    return;
}

NTSTATUS DriverDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	
	ULONG IoControlCode = Irp->Tail.Overlay.CurrentStackLocation->Parameters.DeviceIoControl.IoControlCode;

	DbgPrint("Control!DriverDispatch IoControlCode=0x%06X\n",IoControlCode);

	PFILE_OBJECT pFileObj;
	PDEVICE_OBJECT pFilterDeviceObject;
	UNICODE_STRING filterName;
	RtlInitUnicodeString(&filterName, L"\\Device\\wp81hcifilter");
	NTSTATUS status = IoGetDeviceObjectPointer(&filterName, FILE_ALL_ACCESS, &pFileObj, &pFilterDeviceObject);
	if (NT_SUCCESS(status)) {
		DbgPrint("Control! pFilterDeviceObject=0x%p Driver=0x%p\n", pFilterDeviceObject, pFilterDeviceObject->DriverObject);

		PDRIVER_OBJECT pFilterDriverObject = pFilterDeviceObject->DriverObject;
		DbgPrint("Control! DriverName=%wZ\n", &(pFilterDriverObject->DriverName));

		// https://stackoverflow.com/questions/5095406/iterating-over-wdm-device-stack
		// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-iogetlowerdeviceobject

		SendAnIoctl(pFilterDeviceObject);
	}
	else
	{
		DbgPrint("Control! IoGetDeviceObjectPointer failed (0x%x)\n", status);
	}
	

	return CompleteIrp(Irp, STATUS_SUCCESS, 0);
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