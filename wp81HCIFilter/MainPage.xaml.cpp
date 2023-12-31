﻿//
// MainPage.xaml.cpp
// Implementation of the MainPage class.
//

#include "pch.h"
#include "MainPage.xaml.h"
#include "Win32Api.h"

using namespace wp81HCIFilter;

using namespace Platform;
using namespace Windows::Foundation;
using namespace Windows::Foundation::Collections;
using namespace Windows::UI::Xaml;
using namespace Windows::UI::Xaml::Controls;
using namespace Windows::UI::Xaml::Controls::Primitives;
using namespace Windows::UI::Xaml::Data;
using namespace Windows::UI::Xaml::Input;
using namespace Windows::UI::Xaml::Media;
using namespace Windows::UI::Xaml::Navigation;
using namespace Windows::Storage;
using namespace concurrency;
using namespace Windows::UI::Core;

#define CONTROL_DEVICE 0x8000

#define IOCTL_FILTER_CONTROL_CMD CTL_CODE(CONTROL_DEVICE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef enum _BTHX_HCI_PACKET_TYPE {
	HciPacketCommand = 0x01,
	HciPacketAclData = 0x02,
	HciPacketEvent = 0x04
} BTHX_HCI_PACKET_TYPE;

#pragma pack(1)
typedef struct _BTHX_HCI_READ_WRITE_CONTEXT {
	ULONG   DataLen;    // Size of Data
	UCHAR   Type;       // Packet Type
	_Field_size_bytes_(DataLen) UCHAR   Data[1];    // Actual data
} BTHX_HCI_READ_WRITE_CONTEXT, *PBTHX_HCI_READ_WRITE_CONTEXT;
#pragma pack(8)

Win32Api win32Api;

MainPage::MainPage()
{
	InitializeComponent();
}

void debug(WCHAR* format, ...)
{
	va_list args;
	va_start(args, format);

	WCHAR buffer[1000];
	_vsnwprintf_s(buffer, sizeof(buffer), format, args);

	OutputDebugStringW(buffer);

	va_end(args);
}

void debugMultiSz(WCHAR *multisz)
{
	WCHAR* c = multisz;
	WCHAR* value = nullptr;
	boolean isFirstString = true;
	do
	{
		if (isFirstString)
		{
			isFirstString = false;
		}
		else
		{
			debug(L",");
		}
		value = c;
		while (*c != L'\0')
		{
			c++;
		}
		c++; // skip \0
		debug(L"%ls\n", value);
	} while (*c != L'\0');
}

void printBufferContent(PVOID buffer, size_t bufSize)
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

	if (bufSize < 1)
	{
		return;
	}

	for (; i<bufSize && i < 608; i++)
	{
		sprintf_s(tempString, 8, "%02X ", p[i]);
		strcat_s(hexString, 256, tempString);

		sprintf_s(tempString, 8, "%c", p[i]>31 && p[i]<127 ? p[i] : '.');
		strcat_s(chrString, 256, tempString);

		if ((i + 1) % 38 == 0)
		{
			debug(L"%S%S\n", hexString, chrString);
			RtlZeroMemory(hexString, 256);
			RtlZeroMemory(chrString, 256);
			multiLine = TRUE;
		}
	}
	length = strlen(hexString);
	if (length != 0)
	{
		CHAR padding[256];
		RtlZeroMemory(padding, 256);
		if (multiLine)
		{
			sprintf_s(padding, 256, "%*s", 3 * (38 - (i % 38)), "");
		}

		debug(L"%S%S%S\n", hexString, padding, chrString);
	}

	if (i == 608)
	{
		debug(L"...\n");
	}
}

void MainPage::UIConsoleAddText(Platform::String ^ text) {
	Dispatcher->RunAsync(
		CoreDispatcherPriority::Normal,
		ref new DispatchedHandler([this, text]()
	{
		TextTest->Text += text;
	}));
}

/// <summary>
/// Invoked when this page is about to be displayed in a Frame.
/// </summary>
/// <param name="e">Event data that describes how this page was reached.  The Parameter
/// property is typically used to configure the page.</param>
void MainPage::OnNavigatedTo(NavigationEventArgs^ e)
{
	(void) e;	// Unused parameter

	TextTest->Text = "Checking test-signed drivers...";

	HKEY HKEY_LOCAL_MACHINE = (HKEY)0x80000002;
	DWORD retCode;

	HKEY controlKey = {};
	retCode = win32Api.RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control", 0, KEY_ALL_ACCESS, &controlKey);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegOpenKeyExW : %d\n", retCode);
		return;
	}

	WCHAR ValueName[16383]; // buffer for value name
	DWORD ValueType;
	PBYTE ValueData = new BYTE[32767];

	DWORD i = 0;
	do
	{
		DWORD ValueNameSize = 16383;
		DWORD ValueDataSize = 32767;
		retCode = win32Api.RegEnumValueW(controlKey, i,
			ValueName,
			&ValueNameSize,
			NULL,
			&ValueType,
			ValueData,
			&ValueDataSize);

		debug(L"retCode %d Value name: %s\n", retCode, ValueName);

		if (wcscmp(L"SystemStartOptions", ValueName) == 0)
		{
			debug(L"Value: %s\n", ValueData);
			if (wcsstr((WCHAR*)ValueData, L"TESTSIGNING"))
			{
				debug(L"OK\n");
				TextTest->Text += L"OK\n";
			}
			else
			{
				TextTest->Text += L"Failed\n";
				TextTest->Text += L"Please enable test-signed drivers to load!!\n";
			}
		}

		i++;
	} while (retCode == ERROR_SUCCESS);
}

void wp81HCIFilter::MainPage::AppBarButton_Click(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e)
{
	Button^ b = (Button^)sender;
	if (b->Tag->ToString() == "Install")
	{
		Install();
	}
	else if (b->Tag->ToString() == "Ioctl")
	{
		SendIoctl();
	}
}

DWORD appendMultiSz(WCHAR* src, WCHAR* dst)
{
	DWORD size = 0;
	WCHAR* s = src;
	WCHAR* d = dst;
	do
	{
		*d = *s;
		s++;
		d++;
		size++;
	} while (*s != L'\0');
	*d = L'\0';
	size++;
	return size;
}

void wp81HCIFilter::MainPage::Install()
{
	TextTest->Text += L"Create driver WP81HCIFilter in registry... ";

	HKEY HKEY_LOCAL_MACHINE = (HKEY)0x80000002;
	DWORD retCode;

	// Configure WP81HCIFilter driver

	HKEY servicesKey = {};
	retCode = win32Api.RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services", 0, KEY_ALL_ACCESS, &servicesKey);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegOpenKeyExW : %d\n", retCode);
		TextTest->Text += L"Failed\n";
		return;
	}

	HKEY wp81driverKey = {};
	retCode = win32Api.RegCreateKeyExW(servicesKey, L"wp81hcifilter", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &wp81driverKey, NULL);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegCreateKeyExW 'wp81hcifilter': %d\n", retCode);
		TextTest->Text += L"Failed\n";
		return;
	}

	PBYTE ValueData = new BYTE[256];

	ZeroMemory(ValueData, 256);
	wcscpy_s((WCHAR*)ValueData, 128, L"WP81 HCI Filter driver");
	retCode = win32Api.RegSetValueExW(wp81driverKey, L"Description", NULL, REG_SZ, ValueData, (wcslen((WCHAR*)ValueData) + 1) * sizeof(WCHAR));
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegSetValueExW 'Description': %d\n", retCode);
		TextTest->Text += L"Failed\n";
		return;
	}

	ZeroMemory(ValueData, 256);
	wcscpy_s((WCHAR*)ValueData, 128, L"wp81HCIFilter");
	retCode = win32Api.RegSetValueExW(wp81driverKey, L"DisplayName", NULL, REG_SZ, ValueData, (wcslen((WCHAR*)ValueData) + 1) * sizeof(WCHAR));
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegSetValueExW 'DisplayName': %d\n", retCode);
		TextTest->Text += L"Failed\n";
		return;
	}

	*(PDWORD)ValueData = 1; // Normal: If the driver fails to load or initialize, startup proceeds, but a warning message appears.
	retCode = win32Api.RegSetValueExW(wp81driverKey, L"ErrorControl", NULL, REG_DWORD, ValueData, 4);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegSetValueExW 'ErrorControl': %d\n", retCode);
		TextTest->Text += L"Failed\n";
		return;
	}

	*(PDWORD)ValueData = 3; // SERVICE_DEMAND_START (started by the PlugAndPlay Manager)
	retCode = win32Api.RegSetValueExW(wp81driverKey, L"Start", NULL, REG_DWORD, ValueData, 4);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegSetValueExW 'Start': %d\n", retCode);
		TextTest->Text += L"Failed\n";
		return;
	}

	*(PDWORD)ValueData = 1; // 	A kernel-mode device driver
	retCode = win32Api.RegSetValueExW(wp81driverKey, L"Type", NULL, REG_DWORD, ValueData, 4);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegSetValueExW 'Type': %d\n", retCode);
		TextTest->Text += L"Failed\n";
		return;
	}

	retCode = win32Api.RegCloseKey(wp81driverKey);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegCloseKey 'wp81hcifilter': %d\n", retCode);
		TextTest->Text += L"Failed\n";
		return;
	}

	retCode = win32Api.RegCloseKey(servicesKey);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegCloseKey 'servicesKey': %d\n", retCode);
		TextTest->Text += L"Failed\n";
		return;
	}

	// Set wp81hcifilter as a lower filter of BTHMINI (the filter is between BTHMINI and QcBluetooth)

	WCHAR *newValueData = (WCHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 5000);
	DWORD newValueDataSize = 0;
	newValueDataSize += appendMultiSz(L"wp81hcifilter", newValueData);
	newValueDataSize++; // add final \0
	debug(L"MultiString:\n");
	debugMultiSz(newValueData);

	HKEY pdoKey = {};
	// lumia 520
	retCode = win32Api.RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Enum\\SystemBusQc\\SMD_BT\\4&315a27b&0&4097", 0, KEY_ALL_ACCESS, &pdoKey);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegOpenKeyExW : %d\n", retCode);
		TextTest->Text += L"Failed\n";
		return;
	}

	retCode = win32Api.RegSetValueExW(pdoKey, L"LowerFilters", NULL, REG_MULTI_SZ, (BYTE*)newValueData, newValueDataSize * 2);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegSetValueExW 'UpperFilters': %d\n", retCode);
		TextTest->Text += L"Failed\n";
		return;
	}

	retCode = win32Api.RegCloseKey(pdoKey);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegCloseKey 'pdoKey': %d\n", retCode);
		TextTest->Text += L"Failed\n";
		return;
	}

	TextTest->Text += L"OK\n";

	TextTest->Text += L"Create driver WP81ControlDevice in registry... ";

	// Configure WP81ControlDevice driver

	retCode = win32Api.RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services", 0, KEY_ALL_ACCESS, &servicesKey);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegOpenKeyExW : %d\n", retCode);
		TextTest->Text += L"Failed\n";
		return;
	}

	retCode = win32Api.RegCreateKeyExW(servicesKey, L"wp81controldevice", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &wp81driverKey, NULL);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegCreateKeyExW 'wp81controldevice': %d\n", retCode);
		TextTest->Text += L"Failed\n";
		return;
	}

	ZeroMemory(ValueData, 256);
	wcscpy_s((WCHAR*)ValueData, 128, L"WP81 Control driver");
	retCode = win32Api.RegSetValueExW(wp81driverKey, L"Description", NULL, REG_SZ, ValueData, (wcslen((WCHAR*)ValueData) + 1) * sizeof(WCHAR));
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegSetValueExW 'Description': %d\n", retCode);
		TextTest->Text += L"Failed\n";
		return;
	}

	ZeroMemory(ValueData, 256);
	wcscpy_s((WCHAR*)ValueData, 128, L"wp81controldevice");
	retCode = win32Api.RegSetValueExW(wp81driverKey, L"DisplayName", NULL, REG_SZ, ValueData, (wcslen((WCHAR*)ValueData) + 1) * sizeof(WCHAR));
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegSetValueExW 'DisplayName': %d\n", retCode);
		TextTest->Text += L"Failed\n";
		return;
	}

	*(PDWORD)ValueData = 1; // Normal: If the driver fails to load or initialize, startup proceeds, but a warning message appears.
	retCode = win32Api.RegSetValueExW(wp81driverKey, L"ErrorControl", NULL, REG_DWORD, ValueData, 4);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegSetValueExW 'ErrorControl': %d\n", retCode);
		TextTest->Text += L"Failed\n";
		return;
	}

	*(PDWORD)ValueData = 1; // SERVICE_SYSTEM_START (started by the IoInitSystem function)
	retCode = win32Api.RegSetValueExW(wp81driverKey, L"Start", NULL, REG_DWORD, ValueData, 4);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegSetValueExW 'Start': %d\n", retCode);
		TextTest->Text += L"Failed\n";
		return;
	}

	*(PDWORD)ValueData = 1; // 	A kernel-mode device driver
	retCode = win32Api.RegSetValueExW(wp81driverKey, L"Type", NULL, REG_DWORD, ValueData, 4);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegSetValueExW 'Type': %d\n", retCode);
		TextTest->Text += L"Failed\n";
		return;
	}

	retCode = win32Api.RegCloseKey(wp81driverKey);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegCloseKey 'wp81controldevice': %d\n", retCode);
		TextTest->Text += L"Failed\n";
		return;
	}

	retCode = win32Api.RegCloseKey(servicesKey);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegCloseKey 'servicesKey': %d\n", retCode);
		TextTest->Text += L"Failed\n";
		return;
	}

	TextTest->Text += L"Install/Update drivers...";

	std::stack<Platform::String ^> fileNames;
	fileNames.push(L"wp81hcifilter.sys");
	fileNames.push(L"wp81controldevice.sys");	
	CopyFiles(fileNames);

}

void MainPage::CopyFiles(std::stack<Platform::String ^> fileNames) {

	if (fileNames.empty())
	{
		UIConsoleAddText(L"You can now reboot the phone to start the service.\n");
		return;
	}

	Platform::String^ fileName = fileNames.top();
	fileNames.pop();

	debug(L"%ls\n", fileName->Data());

	UIConsoleAddText(L"Update " + fileName + L"...");

	Uri^ uri = ref new Uri(L"ms-appx:///Payload/" + fileName);
	create_task(StorageFile::GetFileFromApplicationUriAsync(uri)).then([=](task<StorageFile^> t)
	{
		StorageFile ^storageFile = t.get();
		Platform::String^ filePath = storageFile->Path;
		debug(L"FilePath : %ls\n", filePath->Data());
		Platform::String ^ newFileName = L"C:\\windows\\system32\\drivers\\" + fileName;
		if (!win32Api.CopyFileW(filePath->Data(), newFileName->Data(), FALSE))
		{
			debug(L"CopyFileW error: %d (32=ERROR_SHARING_VIOLATION)\n", GetLastError());
			UIConsoleAddText(L"Failed\n");
		}
		else
		{
			debug(L"File copied\n");
			UIConsoleAddText(L"OK\n");
			CopyFiles(fileNames);
		}
	});
}

void wp81HCIFilter::MainPage::SendIoctl()
{
	TextTest->Text += L"Calling device control...";
	create_task([this]()
	{
		// lumia 520
		HANDLE hDevice = win32Api.CreateFileW(L"\\\\.\\wp81controldevice", GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
		if (hDevice == INVALID_HANDLE_VALUE)
		{
			debug(L"Failed to open device! 0x%X\n", GetLastError());
			UIConsoleAddText(L"Failed to open device.\n");
			return;
		}

		UCHAR* pInputBuffer1 = (UCHAR*)malloc(4);
		PVOID pOutputBuffer1 = malloc(262);
		DWORD information1;
		BOOL success;

		pInputBuffer1[0] = 0x04;
		pInputBuffer1[1] = 0x00;
		pInputBuffer1[2] = 0x00;
		pInputBuffer1[3] = 0x00;
		printBufferContent(pInputBuffer1, 4);
		success = win32Api.DeviceIoControl(hDevice, 0x410413, pInputBuffer1, 4, pOutputBuffer1, 262, &information1, nullptr);
		if (success)
		{
			debug(L"1st call of control device succeeded! information1=%u\n", information1);
			UIConsoleAddText(L"succeeded!\n");
			printBufferContent(pOutputBuffer1, information1);
		}
		else
		{
			debug(L"1st call of control device failed! 0x%X\n", GetLastError());
			UIConsoleAddText(L"failed!\n");
		}

		free(pInputBuffer1);
		free(pOutputBuffer1);
		CloseHandle(hDevice);
	});
	create_task([this]()
	{
		// lumia 520
		HANDLE hDevice = win32Api.CreateFileW(L"\\\\.\\wp81controldevice", GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
		if (hDevice == INVALID_HANDLE_VALUE)
		{
			debug(L"Failed to open device! 0x%X\n", GetLastError());
			UIConsoleAddText(L"Failed to open device.\n");
			return;
		}

		UCHAR* pInputBuffer2 = (UCHAR*)malloc(8);
		PVOID pOutputBuffer2 = malloc(4);
		DWORD information2;
		BOOL success;

		//OpCode=0x1009 INFORMATIONAL_PARAMETERS:READ_BD_ADDR
		//03 00 00 00 01 09 10 00
		pInputBuffer2[0] = 0x03;
		pInputBuffer2[1] = 0x00;
		pInputBuffer2[2] = 0x00;
		pInputBuffer2[3] = 0x00;
		pInputBuffer2[4] = 0x01;
		pInputBuffer2[5] = 0x09;
		pInputBuffer2[6] = 0x10;
		pInputBuffer2[7] = 0x00;
		printBufferContent(pInputBuffer2, 8);
		success = win32Api.DeviceIoControl(hDevice, 0x41040F, pInputBuffer2, 8, pOutputBuffer2, 4, &information2, nullptr);
		if (success)
		{
			debug(L"2nd call of control device succeeded! information2=%u\n", information2);
			UIConsoleAddText(L"succeeded!\n");
			printBufferContent(pOutputBuffer2, information2);
		}
		else
		{
			debug(L"2nd call of control device failed! 0x%X\n", GetLastError());
			UIConsoleAddText(L"failed!\n");
		}

		free(pInputBuffer2);
		free(pOutputBuffer2);
		CloseHandle(hDevice);
	});
}