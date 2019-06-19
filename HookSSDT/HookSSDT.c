#include	"precomp.h"

ULONG g_OldFuncOffset;
NTTERMINATEPROCESS NtTerminateProcess = NULL;


NTSTATUS	DriverEntry(
	IN	PDRIVER_OBJECT	_pDriverObject ,
	IN	PUNICODE_STRING	_pRegistryPath
)
{
	NTSTATUS	Status = STATUS_SUCCESS;
	UNICODE_STRING	LinkName;
	UNICODE_STRING	DeviceName;
	PDEVICE_OBJECT	pDevObj;

	RtlInitUnicodeString(
		&DeviceName ,
		L"\\Device\\PowerfulGun_HookSSDT" );
	//�����豸
	Status = IoCreateDevice(
		_pDriverObject ,
		0 ,
		&DeviceName ,
		FILE_DEVICE_UNKNOWN ,
		0 ,
		FALSE ,
		&pDevObj );
	if (!NT_SUCCESS( Status ))
	{
		DEBUG( DL_ERROR ,
			"Fail to create device !\n" );
		return	Status;
	}

	//��������������
	RtlInitUnicodeString(
		&LinkName ,
		L"\\DosDevices\\PowerfulGun_HookSSDT" );

	Status = IoCreateSymbolicLink(
		&LinkName , &DeviceName );
	if (!NT_SUCCESS( Status ))
	{
		DEBUG( DL_ERROR ,
			"Fail to create symbolic name !\n" );
		IoDeleteDevice( pDevObj );
		return	Status;
	}

	//���������ַ�����
	for (ULONG i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		_pDriverObject->MajorFunction[i] = _DefaultDispatch;
	}
	_pDriverObject->DriverUnload = _DriverUnload;

	//���SSDT��ַ
	KeServiceDescriptorTable =
		(PSYSTEM_SERVICE_TABLE)
		_GetKeServiceDescriptorTable64();

	//hook
	_HookSSDT();

	return	STATUS_SUCCESS;
}


/*
�ú���Ϊ�����ַ�������Ĭ�ϴ�����
���з��ز����ɹ�����
*/
NTSTATUS	_DefaultDispatch(
	IN	PDEVICE_OBJECT	_pDevObj ,
	IN	PIRP	_pIrp
)
{
	_pIrp->IoStatus.Status = STATUS_SUCCESS;
	_pIrp->IoStatus.Information = 0;
	IoCompleteRequest( _pIrp , IO_NO_INCREMENT );
	return	STATUS_SUCCESS;
}


/*
����ֹͣʱ�Ĳ���
*/
VOID	_DriverUnload(
	IN	PDRIVER_OBJECT	_pDriverObject
)
{
	UNICODE_STRING	LinkName;

	RtlInitUnicodeString(
		&LinkName ,
		L"\\DosDevices\\PowerfulGun_HookSSDT" );
	IoDeleteSymbolicLink( &LinkName );
	IoDeleteDevice( _pDriverObject->DeviceObject );

	//�ָ�SSDT
	_UnhookSSDT();
}


/*
�ú����������ں����ҵ�SSDT�ĵ�ַ
*/
ULONGLONG	_GetKeServiceDescriptorTable64()
{
	PUCHAR	StartSearchAddress =
		(PUCHAR)__readmsr( 0xc0000082 );
	PUCHAR	EndSearchAddress =
		StartSearchAddress + 0x500;
	UCHAR	b1 = 0 , b2 = 0 , b3 = 0;
	ULONG	Offset = 0;
	ULONGLONG	Addr = 0;

	for (
		PUCHAR	i = StartSearchAddress;
		i < EndSearchAddress;
		i++
		)
	{
		if (MmIsAddressValid( i )
			&& MmIsAddressValid( i + 1 )
			&& MmIsAddressValid( i + 2 ))
		{
			b1 = *i;
			b2 = *(i + 1);
			b3 = *(i + 2);
			if (b1 == 0x4c
				&& b2 == 0x8d
				&& b3 == 0x15) //������4c8d15
			{
				memcpy( &Offset , i + 3 , 4 );
				Addr = (ULONGLONG)Offset
					+ (ULONGLONG)i + 7;
				return	Addr;
			}
		}
	} // end for

	return	0;
}


/*

*/
VOID	_HookSSDT()
{
	PULONG	ServiceTableBase = NULL;
	KIRQL	Irql;

	//���old������ַ
	NtTerminateProcess =
		(NTTERMINATEPROCESS)_GetSSDTFuncAddr( 41 );
	DEBUG( DL_INFO ,
		"_HookSSDT: Old NtTerminateProcess:%p \n" ,
		NtTerminateProcess );

	//�޸�KebugCheckEx�����Ĵ���
	_FuckKeBugCheckEx();

	//��þɺ�����ַ
	ServiceTableBase =
		(PULONG)KeServiceDescriptorTable->ServiceTableBase;
	g_OldFuncOffset = ServiceTableBase[41];

	//��NTTerminateProcess�����ĵ�ַ
	//�ĳ�KeBugCheckEx�ĵ�ַ
	Irql = WPOFFx64();
	ServiceTableBase[41] =
		_GetOffsetAddress( (ULONGLONG)KeBugCheckEx );
	WPONx64( Irql );

	DEBUG( DL_INFO ,
		"KeBugCheckEx: %p" , KeBugCheckEx );
	DEBUG( DL_INFO ,
		"New NtTerminateProcess: %p" , _GetSSDTFuncAddr( 41 ) );
}


/*
�ú�����SSDT�в���Ŀ�꺯����ַ
����:	
ULONG id	Ŀ�꺯����SSDT�е�id
����ֵ:	ULONGLONG
*/
ULONGLONG	_GetSSDTFuncAddr(
	IN	ULONG	_id
)
{
	ULONG	dwFuncOffset = 0;
	PULONG	ServiceTableBase = NULL;

	ServiceTableBase =
		(PULONG)KeServiceDescriptorTable->ServiceTableBase;
	dwFuncOffset = ServiceTableBase[_id];
	dwFuncOffset = dwFuncOffset >> 4;

	return	(ULONGLONG)dwFuncOffset + (ULONGLONG)ServiceTableBase;
}


/*
�ú����޸�KeBugCheckEx�����Ĵ���ʹ��ָ��������ת���Լ�������������
*/
VOID	_FuckKeBugCheckEx()
{
	KIRQL	Irql;
	ULONGLONG	MyFun;
	UCHAR InlineCode[] = 
		"\x48\xB8\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\xFF\xE0";

	MyFun=(ULONGLONG)_Fake_NtTerminateProcess;

	//���Լ�������ַд��InlineCode
	memcpy( InlineCode + 2 , &MyFun , 8 );

	//�ر�д����
	Irql = WPOFFx64();

	//�޸�KeBugCheckEx�Ĵ���
	memset( KeBugCheckEx , 0x90 , 15 );
	memcpy( KeBugCheckEx , InlineCode , 12 );

	//��д����
	WPONx64( Irql );
}


/*
�ر�д����
*/
KIRQL WPOFFx64()
{
	KIRQL irql = KeRaiseIrqlToDpcLevel();
	UINT64 cr0 = __readcr0();
	cr0 &= 0xfffffffffffeffff;
	__writecr0( cr0 );
	_disable();
	return irql;
}

/*
��д����
*/
VOID WPONx64( KIRQL irql )
{
	UINT64 cr0 = __readcr0();
	cr0 |= 0x10000;
	_enable();
	__writecr0( cr0 );
	KeLowerIrql( irql );
}


/*
�ú���ͨ����ʵ��ַ�������ServiceTableBase�е�ƫ�Ƶ�ַ
*/
ULONG	_GetOffsetAddress(
	IN	ULONGLONG	_FuncAddr
)
{
	ULONG	dwOffset = 0;
	PULONG	ServiceTableBase = NULL;

	ServiceTableBase =
		(PULONG)KeServiceDescriptorTable->ServiceTableBase;
	dwOffset = (ULONG)
		(_FuncAddr - (ULONGLONG)ServiceTableBase);
	return	dwOffset << 4;
}


/*

*/
NTSTATUS	_Fake_NtTerminateProcess(
	IN	HANDLE	_ProcessHandle ,
	IN	NTSTATUS	_ExitStatus
)
{
	PEPROCESS	pEProcess;
	NTSTATUS	Status;

	DEBUG( DL_INFO ,
		"[_Fake_NtTerminateProcess]\n" );

	Status =
		ObReferenceObjectByHandle(
		_ProcessHandle ,
		GENERIC_READ ,
		*PsProcessType ,
		KernelMode ,
		&pEProcess ,
		NULL );
	if (!NT_SUCCESS( Status ))
	{
		DEBUG( DL_INFO ,
			"[_Fake_NtTerminateProcess]: Fail to get PEPROCESS !\n" );
	}

	if (!_stricmp(
		PsGetProcessImageFileName( pEProcess ) ,
		"calc.exe" ))
	{
		return	STATUS_ACCESS_DENIED;
	}
	
	return	NtTerminateProcess(
		_ProcessHandle , _ExitStatus );
}


/*

*/
VOID	_UnhookSSDT()
{
	KIRQL	Irql;
	PULONG	ServiceTableBase = NULL;

	ServiceTableBase = (PULONG)
		KeServiceDescriptorTable->ServiceTableBase;

	Irql = WPOFFx64();

	ServiceTableBase[41] =
		_GetOffsetAddress( (ULONGLONG)NtTerminateProcess );

	WPONx64( Irql );

	//��ʱ���ָ�KeBugCheckEx�Ĵ���
}