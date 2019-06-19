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
	//创建设备
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

	//创建符号链接名
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

	//设置驱动分发函数
	for (ULONG i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		_pDriverObject->MajorFunction[i] = _DefaultDispatch;
	}
	_pDriverObject->DriverUnload = _DriverUnload;

	//获得SSDT地址
	KeServiceDescriptorTable =
		(PSYSTEM_SERVICE_TABLE)
		_GetKeServiceDescriptorTable64();

	//hook
	_HookSSDT();

	return	STATUS_SUCCESS;
}


/*
该函数为驱动分发函数的默认处理函数
其中返回操作成功即可
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
驱动停止时的操作
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

	//恢复SSDT
	_UnhookSSDT();
}


/*
该函数负责在内核中找到SSDT的地址
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
				&& b3 == 0x15) //特征码4c8d15
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

	//获得old函数地址
	NtTerminateProcess =
		(NTTERMINATEPROCESS)_GetSSDTFuncAddr( 41 );
	DEBUG( DL_INFO ,
		"_HookSSDT: Old NtTerminateProcess:%p \n" ,
		NtTerminateProcess );

	//修改KebugCheckEx函数的代码
	_FuckKeBugCheckEx();

	//获得旧函数地址
	ServiceTableBase =
		(PULONG)KeServiceDescriptorTable->ServiceTableBase;
	g_OldFuncOffset = ServiceTableBase[41];

	//将NTTerminateProcess函数的地址
	//改成KeBugCheckEx的地址
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
该函数在SSDT中查找目标函数地址
参数:	
ULONG id	目标函数在SSDT中的id
返回值:	ULONGLONG
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
该函数修改KeBugCheckEx函数的代码使其指令流程跳转到自己的驱动处理函数
*/
VOID	_FuckKeBugCheckEx()
{
	KIRQL	Irql;
	ULONGLONG	MyFun;
	UCHAR InlineCode[] = 
		"\x48\xB8\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\xFF\xE0";

	MyFun=(ULONGLONG)_Fake_NtTerminateProcess;

	//将自己函数地址写入InlineCode
	memcpy( InlineCode + 2 , &MyFun , 8 );

	//关闭写保护
	Irql = WPOFFx64();

	//修改KeBugCheckEx的代码
	memset( KeBugCheckEx , 0x90 , 15 );
	memcpy( KeBugCheckEx , InlineCode , 12 );

	//打开写保护
	WPONx64( Irql );
}


/*
关闭写保护
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
打开写保护
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
该函数通过真实地址计算出在ServiceTableBase中的偏移地址
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

	//暂时不恢复KeBugCheckEx的代码
}