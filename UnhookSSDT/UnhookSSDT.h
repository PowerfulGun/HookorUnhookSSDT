#ifndef UNHOOK_H
#define	UNHOOK_H


#define IOCTL_ClrSSDTHOOK	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS) //Clear ssdt hook
#define IOCTL_GetKiSrvTab	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS) //Get KiServiceTable
#define IOCTL_GetFuncAddr	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS) //Get function address


typedef UINT64( __fastcall *SCFN )(UINT64 , UINT64);
SCFN scfn;


//
// SSDT½á¹¹Ìå
//
typedef struct _SYSTEM_SERVICE_TABLE {
	PVOID  		ServiceTableBase;
	PVOID  		ServiceCounterTableBase;
	ULONGLONG  	NumberOfServices;
	PVOID  		ParamTableBase;
} SYSTEM_SERVICE_TABLE , *PSYSTEM_SERVICE_TABLE;
PSYSTEM_SERVICE_TABLE KeServiceDescriptorTable;


typedef struct _UNHOOK_SSDT64 {
	ULONGLONG Address;
	ULONGLONG id;
}UNHOOK_SSDT64 , *PUNHOOK_SSDT64;


NTSTATUS	_DefaultDispatch(
	IN	PDEVICE_OBJECT	_pDevObj ,
	IN	PIRP	_pIrp
);

NTSTATUS	_DeviceControlDispatch(
	IN	PDEVICE_OBJECT	_pDevObj ,
	IN	PIRP	_pIrp
);

VOID	_DriverUnload(
	IN	PDRIVER_OBJECT	_pDriverObject
);

ULONGLONG	_GetKeServiceDescriptorTable64();

ULONGLONG	_GetSSDTFuncAddr(
	IN	ULONG	_id
);

VOID	_UnhookSSDT(
	IN	PUNHOOK_SSDT64	_pUnhookSSDT
);

KIRQL WPOFFx64();

VOID WPONx64( KIRQL irql );

ULONG	_GetOffsetAddress(
	IN	ULONGLONG	_FuncAddr
);

VOID Initxxxx();


#endif // !UNHOOK_H
