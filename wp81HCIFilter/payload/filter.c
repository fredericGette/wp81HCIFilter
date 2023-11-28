// bcdedit /store f:\EFIESP\efi\Microsoft\Boot\BCD /set {default} bootlog Yes
// bcdedit /store f:\EFIESP\efi\Microsoft\Boot\BCD /set {default} testsigning yes
//
// set PATH=C:\Program Files (x86)\Microsoft Visual Studio 12.0\Common7\IDE\;C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC\bin\x86_arm;C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC\bin;%PATH%
//

#include <ntifs.h>
#include <wdf.h>
#include <ntstrsafe.h>

// https://www.osr.com/nt-insider/2017-issue1/making-device-objects-accessible-safe/

typedef struct _DEVICEFILTER_CONTEXT
{
	CHAR Name[32];
} DEVICEFILTER_CONTEXT, *PDEVICEFILTER_CONTEXT;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICEFILTER_CONTEXT, GetFilterContext);

typedef struct _COMPLETION_CONTEXT
{
	CHAR Name[32];
    ULONG uid;
} COMPLETION_CONTEXT, *PCOMPLETION_CONTEXT;


VOID printBufferContent(PVOID buffer, size_t bufSize, CHAR* Name, ULONG uid)
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
			DbgPrint("HCI!%s!%08X!%s%s", Name, uid, hexString, chrString);
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

		DbgPrint("HCI!%s!%08X!%s%s%s",Name, uid, hexString, padding, chrString);
	}

	if (i == 608)
	{
		DbgPrint("HCI!%s!%08X!...\n",Name, uid);
	}	
}

VOID
FilterRequestCompletionRoutine(
    IN WDFREQUEST                  Request,
    IN WDFIOTARGET                 Target,
    PWDF_REQUEST_COMPLETION_PARAMS CompletionParams,
    IN WDFCONTEXT                  Context
   )
{
    UNREFERENCED_PARAMETER(Target);
	
	NTSTATUS status;
	PCOMPLETION_CONTEXT completionContext = Context;
	size_t OutputBufferLength;
	PIRP irp;
	UCHAR MajorFunction;
	PVOID  buffer = NULL;
	size_t  bufSize = 0;
	ULONG IoControlCode;

	irp = WdfRequestWdmGetIrp(Request);
	MajorFunction = irp->Tail.Overlay.CurrentStackLocation->MajorFunction;
		
	if (MajorFunction == IRP_MJ_DEVICE_CONTROL || MajorFunction == IRP_MJ_INTERNAL_DEVICE_CONTROL)
	{
		IoControlCode = irp->Tail.Overlay.CurrentStackLocation->Parameters.DeviceIoControl.IoControlCode;

		// Looks like this is the real OutputBufferLength
		OutputBufferLength = CompletionParams->IoStatus.Information;

		DbgPrint("HCI!%s!%08X!Complete IoControlCode=0x%X OutputBufferLength=%u Status=0x%X\n", completionContext->Name, completionContext->uid, IoControlCode, OutputBufferLength, CompletionParams->IoStatus.Status);

		if (OutputBufferLength > 0)
		{
			status = WdfRequestRetrieveOutputBuffer(Request, OutputBufferLength, &buffer, &bufSize );
			if (!NT_SUCCESS(status)) {
				DbgPrint("HCI!%s!%08X!WdfRequestRetrieveOutputBuffer failed: 0x%x\n", completionContext->Name, completionContext->uid, status);
				goto exit;
			}
			printBufferContent(buffer, OutputBufferLength, completionContext->Name, completionContext->uid);
		}
	}
	
exit:
    ExFreePoolWithTag(completionContext, 'wp81');
    WdfRequestComplete(Request, CompletionParams->IoStatus.Status);

    return;
}


VOID
FilterForwardRequestWithCompletionRoutine(
    IN WDFREQUEST Request,
    IN WDFIOTARGET Target,
	IN PDEVICEFILTER_CONTEXT deviceContext,
    ULONG uid
    )
{
    BOOLEAN ret;
    NTSTATUS status;
    PCOMPLETION_CONTEXT completionContext;

    //
    // The following function essentially copies the content of
    // current stack location of the underlying IRP to the next one. 
    //
    WdfRequestFormatRequestUsingCurrentType(Request);

    completionContext = ExAllocatePoolWithTag(PagedPool, sizeof(COMPLETION_CONTEXT), 'wp81');
    RtlCopyMemory(completionContext->Name, deviceContext->Name, 32);
    completionContext->uid = uid;

    WdfRequestSetCompletionRoutine(Request,
                                FilterRequestCompletionRoutine,
                                completionContext);

    ret = WdfRequestSend(Request,
                         Target,
                         WDF_NO_SEND_OPTIONS);

    if (ret == FALSE) {
        status = WdfRequestGetStatus (Request);
        DbgPrint("HCI!%s!%08X!WdfRequestSend failed: 0x%x\n",deviceContext->Name, uid, status);
        WdfRequestComplete(Request, status);
    }

    return;
}

VOID
FilterForwardRequest(
    IN WDFREQUEST Request,
    IN WDFIOTARGET Target,
	IN PDEVICEFILTER_CONTEXT deviceContext
    )
{
    WDF_REQUEST_SEND_OPTIONS options;
    BOOLEAN ret;
    NTSTATUS status;

    //
    // We are not interested in post processing the IRP so 
    // fire and forget.
    //
    WDF_REQUEST_SEND_OPTIONS_INIT(&options,
                                  WDF_REQUEST_SEND_OPTION_SEND_AND_FORGET);

    ret = WdfRequestSend(Request, Target, &options);

    if (ret == FALSE) {
        status = WdfRequestGetStatus (Request);
        DbgPrint("HCI!%s!WdfRequestSend failed: 0x%x\n",deviceContext->Name, status);
        WdfRequestComplete(Request, status);
    }

    return;
}

VOID
FilterEvtIoDeviceControl(
    IN WDFQUEUE      Queue,
    IN WDFREQUEST    Request,
    IN size_t        OutputBufferLength,
    IN size_t        InputBufferLength,
    IN ULONG         IoControlCode
    )
{
    WDFDEVICE device;
    NTSTATUS status;
    PVOID  buffer = NULL;
	size_t  bufSize = 0;
    ULONG seed = 1;
    ULONG uid;

    uid = RtlRandomEx(&seed);

    //DbgPrint("HCI!Begin FilterEvtIoDeviceControl\n");

    device = WdfIoQueueGetDevice(Queue);
	PDEVICEFILTER_CONTEXT deviceContext = GetFilterContext(device);
			
	DbgPrint("HCI!%s!%08X!Receive IoControlCode=0x%X InputBufferLength=%u OutputBufferLength=%u\n",deviceContext->Name, uid, IoControlCode, InputBufferLength, OutputBufferLength);
	
    if (InputBufferLength > 0) {
        status = WdfRequestRetrieveInputBuffer(Request, InputBufferLength, &buffer, &bufSize);
        if (!NT_SUCCESS(status)) {
            DbgPrint("HCI!%s!%08X!WdfRequestRetrieveInputBuffer failed: 0x%x\n", deviceContext->Name, uid, status);
            WdfRequestComplete(Request, status);
            return;
        }
        printBufferContent(buffer, bufSize, deviceContext->Name, uid);
    }

    FilterForwardRequestWithCompletionRoutine(Request, WdfDeviceGetIoTarget(device), deviceContext, uid);
	//FilterForwardRequest(Request, WdfDeviceGetIoTarget(device), deviceContext);

	//DbgPrint("HCI!%s!End FilterEvtIoDeviceControl\n",deviceContext->Name);

    return;
}

NTSTATUS EvtDriverDeviceAdd(WDFDRIVER  Driver, PWDFDEVICE_INIT  DeviceInit)
{
    UNREFERENCED_PARAMETER(Driver);
	NTSTATUS                        status;
    WDFDEVICE                       device;    
    WDF_OBJECT_ATTRIBUTES           deviceAttributes;
	WDF_IO_QUEUE_CONFIG     		ioQueueConfig;
    
	DbgPrint("HCI!Begin EvtDriverDeviceAdd\n");

    //
    // Tell the framework that you are filter driver. Framework
    // takes care of inherting all the device flags & characterstics
    // from the lower device you are attaching to.
    //
    WdfFdoInitSetFilter(DeviceInit);

    //
    // Set device attributes
    //
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, DEVICEFILTER_CONTEXT);
 
	//
    // Create a framework device object.  This call will in turn create
    // a WDM deviceobject, attach to the lower stack and set the
    // appropriate flags and attributes.
    //
    status = WdfDeviceCreate(
        &DeviceInit,
        &deviceAttributes,
        &device
        );
    if (!NT_SUCCESS(status))
    {
        DbgPrint("HCI!WdfDeviceCreate failed with Status code 0x%x\n", status);
        goto exit;
    }
	
	PDRIVER_OBJECT pWdmDriver = WdfDriverWdmGetDriverObject(Driver);
	PDEVICE_OBJECT pWdmPDO = WdfDeviceWdmGetPhysicalDevice(device);
	PDEVICE_OBJECT pWdmFDO = WdfDeviceWdmGetDeviceObject(device);
	PDEVICE_OBJECT pWdmLowerDO = WdfDeviceWdmGetAttachedDevice(device);
	
	DbgPrint("HCI!Driver 0x%p, FDO 0x%p, PDO 0x%p, Lower 0x%p\n", pWdmDriver, pWdmFDO, pWdmPDO, pWdmLowerDO);
	
	DbgPrint("HCI!FDO Type=%d (3=Device), Size=%d, Driver=0x%p, NextDevice=0x%p, AttachedDevice=0x%p\n",pWdmFDO->Type, pWdmFDO->Size, pWdmFDO->DriverObject, pWdmFDO->NextDevice, pWdmFDO->AttachedDevice);
	DbgPrint("HCI!PDO Type=%d (3=Device), Size=%d, Driver=0x%p, NextDevice=0x%p, AttachedDevice=0x%p\n",pWdmPDO->Type, pWdmPDO->Size, pWdmPDO->DriverObject, pWdmPDO->NextDevice, pWdmPDO->AttachedDevice);
	DbgPrint("HCI!PDO2 Type=%d (3=Device), Size=%d, Driver=0x%p, NextDevice=0x%p, AttachedDevice=0x%p\n",pWdmPDO->NextDevice->Type, pWdmPDO->NextDevice->Size, pWdmPDO->NextDevice->DriverObject, pWdmPDO->NextDevice->NextDevice, pWdmPDO->NextDevice->AttachedDevice);
	DbgPrint("HCI!LowerDO Type=%d (3=Device), Size=%d, Driver=0x%p, NextDevice=0x%p, AttachedDevice=0x%p\n",pWdmLowerDO->Type, pWdmLowerDO->Size, pWdmLowerDO->DriverObject, pWdmLowerDO->NextDevice, pWdmLowerDO->AttachedDevice);
	
	PDRIVER_OBJECT pWdmDriver2 = pWdmFDO->DriverObject;
	DbgPrint("HCI!FDO Driver Type=%d (4=Driver), Device=0x%p, DriverName=%wZ, HardwareDatabase=%wZ\n",pWdmDriver2->Type, pWdmDriver2->DeviceObject, &(pWdmDriver2->DriverName), pWdmDriver2->HardwareDatabase);
	
	pWdmDriver2 = pWdmPDO->DriverObject;
	DbgPrint("HCI!PDO Driver Type=%d (4=Driver), Device=0x%p, DriverName=%wZ, HardwareDatabase=%wZ\n",pWdmDriver2->Type, pWdmDriver2->DeviceObject, &(pWdmDriver2->DriverName), pWdmDriver2->HardwareDatabase);

	pWdmDriver2 = pWdmLowerDO->DriverObject;
	DbgPrint("HCI!LowerDO Driver Type=%d (4=Driver), Device=0x%p, DriverName=%wZ, HardwareDatabase=%wZ\n",pWdmDriver2->Type, pWdmDriver2->DeviceObject, &(pWdmDriver2->DriverName), pWdmDriver2->HardwareDatabase);
	
				
	WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&ioQueueConfig, WdfIoQueueDispatchParallel);	
	ioQueueConfig.EvtIoDeviceControl = FilterEvtIoDeviceControl;
	
	status = WdfIoQueueCreate(device,
                            &ioQueueConfig,
                            WDF_NO_OBJECT_ATTRIBUTES,
                            WDF_NO_HANDLE // pointer to default queue
                            );
    if (!NT_SUCCESS(status)) {
        DbgPrint("HCI!WdfIoQueueCreate failed 0x%x\n", status);
        goto exit;
    }   
	
    // Create a prefix name for the logs of this device.
	PDEVICEFILTER_CONTEXT deviceContext = GetFilterContext(device);
	CHAR fullDriverName[32] = {0};
	RtlStringCbPrintfA(fullDriverName, 32-1, "%wZ", &(pWdmLowerDO->DriverObject->DriverName));
	CHAR *shortDriverName = fullDriverName;
	if (RtlCompareMemory(fullDriverName, "\\Driver\\", 8) == 8)
	{
		shortDriverName = fullDriverName + 8;
	}
	CHAR buffer[32];
	RtlZeroMemory(buffer, 32);
	RtlStringCbPrintfA(buffer, 32-1, "%p-%s", pWdmLowerDO->DriverObject->DeviceObject, shortDriverName);
	RtlCopyMemory(deviceContext->Name, buffer, 32);
	
    // Store this device object pointer in registry (for the control device).
    WDFKEY hKey = NULL;
    UNICODE_STRING valueName;
    status = WdfDeviceOpenRegistryKey(device,
                                      PLUGPLAY_REGKEY_DEVICE,
                                      STANDARD_RIGHTS_ALL,
                                      WDF_NO_OBJECT_ATTRIBUTES,
                                      &hKey);
    if (NT_SUCCESS (status)) {
        RtlInitUnicodeString(&valueName, L"wp81DeviceObjectPointer");
        status = WdfRegistryAssignULong (hKey,
                                  &valueName,
                                  (ULONG)pWdmFDO
                                );
        if (!NT_SUCCESS(status)) {
            DbgPrint("HCI!WdfRegistryAssignULong failed 0x%x\n", status);
        }
        WdfRegistryClose(hKey);
    }
    else {
        DbgPrint("HCI!WdfDeviceOpenRegistryKey failed 0x%x\n", status);
    }

			
exit:    
	DbgPrint("HCI!End EvtDriverDeviceAdd\n");
    return status;
}

void EvtCleanupCallback(WDFOBJECT DriverObject) 
{
    UNREFERENCED_PARAMETER(DriverObject);
	
	DbgPrint("HCI!Begin EvtCleanupCallback\n");
	DbgPrint("HCI!End EvtCleanupCallback\n");
}

// DriverEntry
NTSTATUS DriverEntry(PDRIVER_OBJECT  DriverObject, PUNICODE_STRING  RegistryPath)
{
	DbgPrint("HCI!Begin DriverEntry\n");
	
    NTSTATUS status;
    WDFDRIVER driver;
    WDF_OBJECT_ATTRIBUTES attributes;
        
    WDF_DRIVER_CONFIG DriverConfig;
    WDF_DRIVER_CONFIG_INIT(
                           &DriverConfig,
                           EvtDriverDeviceAdd
                           );

    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.EvtCleanupCallback = EvtCleanupCallback;

    status = WdfDriverCreate(
        DriverObject,
        RegistryPath,
        &attributes,
        &DriverConfig,
        &driver
        );

	DbgPrint("HCI!Driver registryPath= %S\n", RegistryPath->Buffer);

	DbgPrint("HCI!End DriverEntry\n");
    return status;
}