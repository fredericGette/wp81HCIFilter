#pragma once

// See https://github.com/tandasat/SecRuntimeSample/blob/master/SecRuntimeSampleNative/Win32Api.h

//
// Service Control Manager object specific access types
//
#define SC_MANAGER_CONNECT             0x0001
#define SC_MANAGER_CREATE_SERVICE      0x0002
#define SC_MANAGER_ENUMERATE_SERVICE   0x0004
#define SC_MANAGER_LOCK                0x0008
#define SC_MANAGER_QUERY_LOCK_STATUS   0x0010
#define SC_MANAGER_MODIFY_BOOT_CONFIG  0x0020

#define SC_MANAGER_ALL_ACCESS          (STANDARD_RIGHTS_REQUIRED      | \
                                        SC_MANAGER_CONNECT            | \
                                        SC_MANAGER_CREATE_SERVICE     | \
                                        SC_MANAGER_ENUMERATE_SERVICE  | \
                                        SC_MANAGER_LOCK               | \
                                        SC_MANAGER_QUERY_LOCK_STATUS  | \
                                        SC_MANAGER_MODIFY_BOOT_CONFIG)

//
// Service object specific access type
//
#define SERVICE_QUERY_CONFIG           0x0001
#define SERVICE_CHANGE_CONFIG          0x0002
#define SERVICE_QUERY_STATUS           0x0004
#define SERVICE_ENUMERATE_DEPENDENTS   0x0008
#define SERVICE_START                  0x0010
#define SERVICE_STOP                   0x0020
#define SERVICE_PAUSE_CONTINUE         0x0040
#define SERVICE_INTERROGATE            0x0080
#define SERVICE_USER_DEFINED_CONTROL   0x0100

#define SERVICE_ALL_ACCESS             (STANDARD_RIGHTS_REQUIRED     | \
                                        SERVICE_QUERY_CONFIG         | \
                                        SERVICE_CHANGE_CONFIG        | \
                                        SERVICE_QUERY_STATUS         | \
                                        SERVICE_ENUMERATE_DEPENDENTS | \
                                        SERVICE_START                | \
                                        SERVICE_STOP                 | \
                                        SERVICE_PAUSE_CONTINUE       | \
                                        SERVICE_INTERROGATE          | \
                                        SERVICE_USER_DEFINED_CONTROL)

//
// Define the method codes for how buffers are passed for I/O and FS controls
//

#define METHOD_BUFFERED                 0
#define METHOD_IN_DIRECT                1
#define METHOD_OUT_DIRECT               2
#define METHOD_NEITHER                  3

#define FILE_ANY_ACCESS                 0
#define FILE_SPECIAL_ACCESS    (FILE_ANY_ACCESS)
#define FILE_READ_ACCESS          ( 0x0001 )    // file & pipe
#define FILE_WRITE_ACCESS         ( 0x0002 )    // file & pipe

//
// Macro definition for defining IOCTL and FSCTL function control codes.  Note
// that function codes 0-2047 are reserved for Microsoft Corporation, and
// 2048-4095 are reserved for customers.
//

#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
)

typedef ACCESS_MASK REGSAM;

typedef struct _STARTUPINFOA {
	DWORD cb;
	LPSTR lpReserved;
	LPSTR lpDesktop;
	LPSTR lpTitle;
	DWORD dwX;
	DWORD dwY;
	DWORD dwXSize;
	DWORD dwYSize;
	DWORD dwXCountChars;
	DWORD dwYCountChars;
	DWORD dwFillAttribute;
	DWORD dwFlags;
	WORD wShowWindow;
	WORD cbReserved2;
	LPBYTE lpReserved2;
	HANDLE hStdInput;
	HANDLE hStdOutput;
	HANDLE hStdError;
} STARTUPINFOA, *LPSTARTUPINFOA;

typedef struct _PROCESS_INFORMATION {
	HANDLE hProcess;
	HANDLE hThread;
	DWORD dwProcessId;
	DWORD dwThreadId;
} PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;

DECLARE_HANDLE(SC_HANDLE);
typedef SC_HANDLE   *LPSC_HANDLE;

typedef struct _BLUETOOTH_FIND_RADIO_PARAMS {
	DWORD   dwSize;             //  IN  sizeof this structure
} BLUETOOTH_FIND_RADIO_PARAMS;

typedef HANDLE      HBLUETOOTH_RADIO_FIND;

#define GET_BITS(field,offset,mask)         ( ( (field) >> (offset) ) & (mask) )
#define GET_BIT(field,offset)               ( GET_BITS(field,offset,0x1) )

#define LMP_3_SLOT_PACKETS(x)               (GET_BIT(x, 0))
#define LMP_5_SLOT_PACKETS(x)               (GET_BIT(x, 1))
#define LMP_ENCRYPTION(x)                   (GET_BIT(x, 2))
#define LMP_SLOT_OFFSET(x)                  (GET_BIT(x, 3))
#define LMP_TIMING_ACCURACY(x)              (GET_BIT(x, 4))
#define LMP_SWITCH(x)                       (GET_BIT(x, 5))
#define LMP_HOLD_MODE(x)                    (GET_BIT(x, 6))
#define LMP_SNIFF_MODE(x)                   (GET_BIT(x, 7))
#define LMP_PARK_MODE(x)                    (GET_BIT(x, 8))
#define LMP_RSSI(x)                         (GET_BIT(x, 9))
#define LMP_CHANNEL_QUALITY_DRIVEN_MODE(x)  (GET_BIT(x,10))
#define LMP_SCO_LINK(x)                     (GET_BIT(x,11))
#define LMP_HV2_PACKETS(x)                  (GET_BIT(x,12))
#define LMP_HV3_PACKETS(x)                  (GET_BIT(x,13))
#define LMP_MU_LAW_LOG(x)                   (GET_BIT(x,14))
#define LMP_A_LAW_LOG(x)                    (GET_BIT(x,15))
#define LMP_CVSD(x)                         (GET_BIT(x,16))
#define LMP_PAGING_SCHEME(x)                (GET_BIT(x,17))
#define LMP_POWER_CONTROL(x)                (GET_BIT(x,18))
#define LMP_TRANSPARENT_SCO_DATA(x)         (GET_BIT(x,19))
#define LMP_FLOW_CONTROL_LAG(x)             (GET_BITS(x,20,0x3))
#define LMP_BROADCAST_ENCRYPTION(x)         (GET_BIT(x,23))
#define LMP_ENHANCED_DATA_RATE_ACL_2MBPS_MODE(x) (GET_BIT(x,25))
#define LMP_ENHANCED_DATA_RATE_ACL_3MBPS_MODE(x) (GET_BIT(x,26))
#define LMP_ENHANCED_INQUIRY_SCAN(x)        (GET_BIT(x,27))
#define LMP_INTERLACED_INQUIRY_SCAN(x)      (GET_BIT(x,28))
#define LMP_INTERLACED_PAGE_SCAN(x)         (GET_BIT(x,29))
#define LMP_RSSI_WITH_INQUIRY_RESULTS(x)    (GET_BIT(x,30))
#define LMP_ESCO_LINK(x)                    (GET_BIT(x,31)) 
#define LMP_EV4_PACKETS(x)                  (GET_BIT(x,0)) //high
#define LMP_EV5_PACKETS(x)                  (GET_BIT(x,1)) //high
#define LMP_AFH_CAPABLE_SLAVE(x)            (GET_BIT(x,3)) //high
#define LMP_AFH_CLASSIFICATION_SLAVE(x)     (GET_BIT(x,4)) //high
#define LMP_BR_EDR_NOT_SUPPORTED(x)         (GET_BIT(x,5)) //high
#define LMP_LE_SUPPORTED(x)                 (GET_BIT(x,6)) //high
#define LMP_3SLOT_EDR_ACL_PACKETS(x)        (GET_BIT(x,7)) //high
#define LMP_5SLOT_EDR_ACL_PACKETS(x)        (GET_BIT(x,8)) //high
#define LMP_SNIFF_SUBRATING(x)              (GET_BIT(x,9)) //high
#define LMP_PAUSE_ENCRYPTION(x)             (GET_BIT(x,10)) //high
#define LMP_AFH_CAPABLE_MASTER(x)           (GET_BIT(x,11)) //high
#define LMP_AFH_CLASSIFICATION_MASTER(x)    (GET_BIT(x,12)) //high
#define LMP_EDR_ESCO_2MBPS_MODE(x)          (GET_BIT(x,13)) //high
#define LMP_EDR_ESCO_3MBPS_MODE(x)          (GET_BIT(x,14)) //high
#define LMP_3SLOT_EDR_ESCO_PACKETS(x)       (GET_BIT(x,15)) //high
#define LMP_EXTENDED_INQUIRY_RESPONSE(x)    (GET_BIT(x,16)) //high
#define LMP_SIMULT_LE_BR_TO_SAME_DEV(x)     (GET_BIT(x,17)) //high
#define LMP_SECURE_SIMPLE_PAIRING(x)        (GET_BIT(x,19)) //high
#define LMP_ENCAPSULATED_PDU(x)             (GET_BIT(x,20)) //high
#define LMP_ERRONEOUS_DATA_REPORTING(x)     (GET_BIT(x,21)) //high
#define LMP_NON_FLUSHABLE_PACKET_BOUNDARY_FLAG(x) (GET_BIT(x,22)) //high
#define LMP_LINK_SUPERVISION_TIMEOUT_CHANGED_EVENT(x) (GET_BIT(x,24)) //high
#define LMP_INQUIRY_RESPONSE_TX_POWER_LEVEL(x)(GET_BIT(x,25)) //high
#define LMP_EXTENDED_FEATURES(x)            (GET_BIT(x,31)) //high
#define LOCAL_RADIO_DISCOVERABLE    (0x00000001)
#define LOCAL_RADIO_CONNECTABLE     (0x00000002)
#define BDIF_ADDRESS			(0x00000001)
#define BDIF_COD                (0x00000002)
#define BDIF_NAME               (0x00000004)
#define BDIF_PAIRED             (0x00000008)
#define BDIF_PERSONAL           (0x00000010)
#define BDIF_CONNECTED          (0x00000020)
#define BDIF_SHORT_NAME         (0x00000040)
#define BDIF_VISIBLE            (0x00000080)
#define BDIF_SSP_SUPPORTED      (0x00000100)
#define BDIF_SSP_PAIRED         (0x00000200)
#define BDIF_SSP_MITM_PROTECTED (0x00000400)
#define BDIF_RSSI               (0x00001000)
#define BDIF_EIR                (0x00002000)
#define BDIF_BR                 (0x00004000)
#define BDIF_LE                 (0x00008000)
#define BDIF_LE_PAIRED          (0x00010000)
#define BDIF_LE_PERSONAL        (0x00020000)
#define BDIF_LE_MITM_PROTECTED  (0x00040000)
#define BDIF_LE_PRIVACY_ENABLED (0x00080000)
#define BDIF_LE_RANDOM_ADDRESS_TYPE \
                                (0x00100000)
#define COD_FORMAT_BIT_OFFSET   (0)
#define COD_MINOR_BIT_OFFSET    (2)
#define COD_MAJOR_BIT_OFFSET    (8 * 1)
#define COD_SERVICE_BIT_OFFSET  (8 * 1 + 5)
#define COD_FORMAT_MASK         (0x000003)
#define COD_MINOR_MASK          (0x0000FC)
#define COD_MAJOR_MASK          (0x001F00)
#define COD_SERVICE_MASK        (0xFFE000)
#define GET_COD_FORMAT(_cod)    ( (_cod) & COD_FORMAT_MASK   >> COD_FORMAT_BIT_OFFSET)
#define GET_COD_MINOR(_cod)     (((_cod) & COD_MINOR_MASK)   >> COD_MINOR_BIT_OFFSET)
#define GET_COD_MAJOR(_cod)     (((_cod) & COD_MAJOR_MASK)   >> COD_MAJOR_BIT_OFFSET)
#define GET_COD_SERVICE(_cod)   (((_cod) & COD_SERVICE_MASK) >> COD_SERVICE_BIT_OFFSET)
#define COD_SERVICE_LIMITED                 (0x0001)
#define COD_SERVICE_POSITIONING             (0x0008)
#define COD_SERVICE_NETWORKING              (0x0010)
#define COD_SERVICE_RENDERING               (0x0020)
#define COD_SERVICE_CAPTURING               (0x0040)
#define COD_SERVICE_OBJECT_XFER             (0x0080)
#define COD_SERVICE_AUDIO                   (0x0100)
#define COD_SERVICE_TELEPHONY               (0x0200)
#define COD_SERVICE_INFORMATION             (0x0400)

extern "C" {
	WINBASEAPI HMODULE WINAPI LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
	WINBASEAPI HMODULE WINAPI GetModuleHandleW(LPCWSTR lpModuleName);

	LONG WINAPI RegOpenKeyExW(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
	LONG WINAPI RegQueryValueExW(HKEY, LPCWSTR, PDWORD, PDWORD, LPBYTE, PDWORD);
	LONG WINAPI RegCloseKey(HKEY);
	LONG WINAPI RegQueryInfoKeyW(HKEY, LPWSTR, PDWORD, PDWORD, PDWORD, PDWORD, PDWORD, PDWORD, PDWORD, PDWORD, PDWORD, PFILETIME);
	LONG WINAPI RegEnumKeyExW(HKEY, DWORD, LPWSTR, PDWORD, PDWORD, LPWSTR, PDWORD, PFILETIME);
	LONG WINAPI RegEnumValueW(HKEY, DWORD, LPWSTR, PDWORD, PDWORD, PDWORD, LPBYTE, PDWORD);
	LONG WINAPI RegSetValueExW(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);
	LONG WINAPI RegCreateKeyExW(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, PDWORD);

	WINBASEAPI HANDLE WINAPI FindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData);
	WINBASEAPI BOOL WINAPI FindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData);
	WINBASEAPI BOOL WINAPI FindClose(HANDLE hFindFile);
	WINBASEAPI HANDLE WINAPI CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
	WINBASEAPI BOOL WINAPI WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);

	WINBASEAPI BOOL WINAPI CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
	WINBASEAPI BOOL WINAPI CloseHandle(HANDLE hObject);

	WINBASEAPI BOOL WINAPI DeviceIoControl(HANDLE hDevice, DWORD dwIoControlCode, LPVOID lpInBuffer, DWORD nInBufferSize, LPVOID lpOutBuffer, DWORD nOutBufferSize, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped);
	WINBASEAPI BOOL	WINAPI GetOverlappedResult(HANDLE hFile, LPOVERLAPPED lpOverlapped, LPDWORD lpNumberOfBytesTransferred, BOOL bWait);
	WINBASEAPI DWORD WINAPI	WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);

	WINBASEAPI BOOL	WINAPI CopyFileW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName, BOOL bFailIfExists);

	WINADVAPI SC_HANDLE WINAPI OpenSCManagerW(LPCWSTR lpMachineName, LPCWSTR lpDatabaseName, DWORD dwDesiredAccess);
	WINADVAPI SC_HANDLE WINAPI CreateServiceW(SC_HANDLE hSCManager, LPCWSTR lpServiceName, LPCWSTR lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCWSTR lpBinaryPathName, LPCWSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCWSTR lpDependencies, LPCWSTR lpServiceStartName, LPCWSTR lpPassword);
	WINADVAPI BOOL WINAPI CloseServiceHandle(SC_HANDLE hSCObject);

	HBLUETOOTH_RADIO_FIND WINAPI BluetoothFindFirstRadio(const BLUETOOTH_FIND_RADIO_PARAMS * pbtfrp, HANDLE * phRadio);
}

#define WIN32API_TOSTRING(x) #x

// Link exported function
#define WIN32API_INIT_PROC(Module, Name)  \
  Name(reinterpret_cast<decltype(&::Name)>( \
      ::GetProcAddress((Module), WIN32API_TOSTRING(Name))))

// Convenientmacro to declare function
#define WIN32API_DEFINE_PROC(Name) const decltype(&::Name) Name

class Win32Api {

private:
	// Returns a base address of KernelBase.dll
	static HMODULE GetKernelBase() {
		return GetBaseAddress(&::DisableThreadLibraryCalls);
	}

	// Returns a base address of the given address
	static HMODULE GetBaseAddress(const void *Address) {
		MEMORY_BASIC_INFORMATION mbi = {};
		if (!::VirtualQuery(Address, &mbi, sizeof(mbi))) {
			return nullptr;
		}
		const auto mz = *reinterpret_cast<WORD *>(mbi.AllocationBase);
		if (mz != IMAGE_DOS_SIGNATURE) {
			return nullptr;
		}
		return reinterpret_cast<HMODULE>(mbi.AllocationBase);
	}

public:
	const HMODULE m_Kernelbase;
	WIN32API_DEFINE_PROC(LoadLibraryExW);
	WIN32API_DEFINE_PROC(GetModuleHandleW);
	WIN32API_DEFINE_PROC(RegOpenKeyExW);
	WIN32API_DEFINE_PROC(RegQueryValueExW);
	WIN32API_DEFINE_PROC(RegCloseKey);
	WIN32API_DEFINE_PROC(RegQueryInfoKeyW);
	WIN32API_DEFINE_PROC(RegEnumKeyExW);
	WIN32API_DEFINE_PROC(RegEnumValueW);
	WIN32API_DEFINE_PROC(RegSetValueExW);
	WIN32API_DEFINE_PROC(RegCreateKeyExW);
	WIN32API_DEFINE_PROC(FindFirstFileW);
	WIN32API_DEFINE_PROC(FindNextFileW);
	WIN32API_DEFINE_PROC(FindClose);
	WIN32API_DEFINE_PROC(CreateFileW);
	WIN32API_DEFINE_PROC(WriteFile);
	WIN32API_DEFINE_PROC(CreateProcessA);
	WIN32API_DEFINE_PROC(CloseHandle);
	WIN32API_DEFINE_PROC(DeviceIoControl);
	WIN32API_DEFINE_PROC(GetOverlappedResult);
	WIN32API_DEFINE_PROC(WaitForSingleObject);
	const HMODULE m_Kernel32legacy;
	WIN32API_DEFINE_PROC(CopyFileW);
	const HMODULE m_SecHost;
	WIN32API_DEFINE_PROC(OpenSCManagerW);
	WIN32API_DEFINE_PROC(CreateServiceW);
	WIN32API_DEFINE_PROC(CloseServiceHandle);
	const HMODULE m_BluetoothApis;
	WIN32API_DEFINE_PROC(BluetoothFindFirstRadio);

	Win32Api()
		: m_Kernelbase(GetKernelBase()),
		WIN32API_INIT_PROC(m_Kernelbase, LoadLibraryExW),
		WIN32API_INIT_PROC(m_Kernelbase, GetModuleHandleW),
		WIN32API_INIT_PROC(m_Kernelbase, RegOpenKeyExW),
		WIN32API_INIT_PROC(m_Kernelbase, RegQueryValueExW),
		WIN32API_INIT_PROC(m_Kernelbase, RegCloseKey),
		WIN32API_INIT_PROC(m_Kernelbase, RegQueryInfoKeyW),
		WIN32API_INIT_PROC(m_Kernelbase, RegEnumKeyExW),
		WIN32API_INIT_PROC(m_Kernelbase, RegEnumValueW),
		WIN32API_INIT_PROC(m_Kernelbase, RegSetValueExW),
		WIN32API_INIT_PROC(m_Kernelbase, RegCreateKeyExW),
		WIN32API_INIT_PROC(m_Kernelbase, FindFirstFileW),
		WIN32API_INIT_PROC(m_Kernelbase, FindNextFileW),
		WIN32API_INIT_PROC(m_Kernelbase, FindClose),
		WIN32API_INIT_PROC(m_Kernelbase, CreateFileW),
		WIN32API_INIT_PROC(m_Kernelbase, WriteFile),
		WIN32API_INIT_PROC(m_Kernelbase, CreateProcessA),
		WIN32API_INIT_PROC(m_Kernelbase, CloseHandle),
		WIN32API_INIT_PROC(m_Kernelbase, DeviceIoControl),
		WIN32API_INIT_PROC(m_Kernelbase, GetOverlappedResult),
		WIN32API_INIT_PROC(m_Kernelbase, WaitForSingleObject),
		m_Kernel32legacy(GetModuleHandleW(L"KERNEL32LEGACY.DLL")),
		WIN32API_INIT_PROC(m_Kernel32legacy, CopyFileW),
		m_SecHost(GetModuleHandleW(L"SECHOST.DLL")),
		WIN32API_INIT_PROC(m_SecHost, OpenSCManagerW),
		WIN32API_INIT_PROC(m_SecHost, CreateServiceW),
		WIN32API_INIT_PROC(m_SecHost, CloseServiceHandle),
		m_BluetoothApis(LoadLibraryExW(L"BLUETOOTHAPIS.DLL", NULL, NULL)),
		WIN32API_INIT_PROC(m_BluetoothApis, BluetoothFindFirstRadio)
	{};

};