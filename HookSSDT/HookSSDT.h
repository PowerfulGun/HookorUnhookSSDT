#ifndef HOOKSSDT_H
#define	HOOKSSDT_H

//
// SSDT�ṹ��
//
typedef struct _SYSTEM_SERVICE_TABLE {
	PVOID  		ServiceTableBase;
	PVOID  		ServiceCounterTableBase;
	ULONGLONG  	NumberOfServices;
	PVOID  		ParamTableBase;
} SYSTEM_SERVICE_TABLE , *PSYSTEM_SERVICE_TABLE;
PSYSTEM_SERVICE_TABLE KeServiceDescriptorTable;


//����NtTerminateProcess����ԭ��
typedef NTSTATUS( __fastcall *NTTERMINATEPROCESS )(
	IN HANDLE ProcessHandle ,
	IN NTSTATUS ExitStatus
	);



//�����ں˺���
NTKERNELAPI
UCHAR *
PsGetProcessImageFileName( PEPROCESS Process );


//������������

VOID	_DriverUnload(
	IN	PDRIVER_OBJECT	_pDriverObject
);

NTSTATUS	_Fake_NtTerminateProcess(
	IN	HANDLE	_ProcessHandle ,
	IN	NTSTATUS	_ExitStatus
);

VOID	_FuckKeBugCheckEx();

ULONGLONG	_GetKeServiceDescriptorTable64();

ULONG	_GetOffsetAddress(
	IN	ULONGLONG	_FuncAddr
);

ULONGLONG	_GetSSDTFuncAddr(
	IN	ULONG	_id
);

VOID	_HookSSDT();

VOID	_UnhookSSDT();

KIRQL WPOFFx64();

VOID WPONx64( KIRQL irql );

NTSTATUS	_DefaultDispatch(
	IN	PDEVICE_OBJECT	_pDevObj ,
	IN	PIRP	_pIrp
);

#endif // !HOOKSSDT_H
