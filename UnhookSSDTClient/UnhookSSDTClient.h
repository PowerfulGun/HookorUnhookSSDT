#ifndef UNHOOKSSDT_H
#define	UNHOOKSSDT_H

#define IOCTL_ClrSSDTHOOK	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS) //Clear ssdt hook
#define IOCTL_GetKiSrvTab	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS) //Get KiServiceTable
#define IOCTL_GetFuncAddr	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS) //Get function address


#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS       ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

#define SystemModuleInformation 11
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)



typedef long( __stdcall *ZWQUERYSYSTEMINFORMATION )(
	IN ULONG SystemInformationClass ,
	IN OUT PVOID SystemInformation ,
	IN ULONG SystemInformationLength ,
	IN PULONG ReturnLength OPTIONAL);
ZWQUERYSYSTEMINFORMATION ZwQuerySystemInformation;


typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY
{
	ULONG Unknow1;
	ULONG Unknow2;
	ULONG Unknow3;
	ULONG Unknow4;
	PVOID64 Base;
	ULONG Size;
	ULONG Flags;
	USHORT Index;
	USHORT NameLength;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	char ImageName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY , *PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG Count;//内核中以加载的模块的个数
	SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION , *PSYSTEM_MODULE_INFORMATION;


typedef struct _UNHOOK_SSDT64 {
	ULONGLONG Address;	//Original address
	ULONGLONG id;
}UNHOOK_SSDT64 , *PUNHOOK_SSDT64;




//
//	函数声明
//

ULONGLONG	_GetFuncOriginalAddress(
	IN	DWORD	_Index
);

VOID	_GetKiServiceTable();

VOID	_GetNtOsBase();

VOID	_GetNtOSImageBase();

VOID	_PrintAllSSDTFunc();

VOID	_UnhookSSDT(
	IN	DWORD	_Index
);

#endif // !UNHOOKSSDT_H
