#include	"precomp.h"




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
		L"\\Device\\PowerfulGun_UnhookSSDT" );
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
		L"\\DosDevices\\PowerfulGun_UnhookSSDT" );

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
	_pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] =
		_DeviceControlDispatch;
	_pDriverObject->DriverUnload = _DriverUnload;

	KeServiceDescriptorTable = (PSYSTEM_SERVICE_TABLE)
		_GetKeServiceDescriptorTable64();

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
		L"\\DosDevices\\PowerfulGun_UnhookSSDT" );
	IoDeleteSymbolicLink( &LinkName );
	IoDeleteDevice( _pDriverObject->DeviceObject );
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
该函数处理应用程序发来的io控制请求
*/
NTSTATUS	_DeviceControlDispatch(
	IN	PDEVICE_OBJECT	_pDevObj ,
	IN	PIRP	_pIrp
)
{
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;
	ULONG	uControlCode;
	ULONG	uInputSize , uOutputSize,uInformation=0;
	PVOID	pInOutBuffer;
	PIO_STACK_LOCATION	pIrpStack;

	pIrpStack = IoGetCurrentIrpStackLocation( _pIrp );
	uControlCode =
		pIrpStack->Parameters.DeviceIoControl.IoControlCode;
	pInOutBuffer = _pIrp->AssociatedIrp.SystemBuffer;
	uInputSize = 
		pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	uOutputSize =
		pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;

	switch (uControlCode)
	{
		case IOCTL_GetKiSrvTab:
			{
				ULONGLONG	ServiceTableBase;
				if (KeServiceDescriptorTable == NULL)
					KeServiceDescriptorTable =(PSYSTEM_SERVICE_TABLE)
					_GetKeServiceDescriptorTable64();
				ServiceTableBase = *(PULONGLONG)
					KeServiceDescriptorTable;
				memcpy( pInOutBuffer , &ServiceTableBase , 8 );
				Status = STATUS_SUCCESS;
				uInformation = 8;
				break;
			}
		case IOCTL_GetFuncAddr:
			{
				ULONGLONG	FuncAddr =
					_GetSSDTFuncAddr(
					*(PULONG)pInOutBuffer );
				memcpy( pInOutBuffer ,
					&FuncAddr , 8 );
				Status = STATUS_SUCCESS;
				uInformation = 8;
				break;
			}
		case IOCTL_ClrSSDTHOOK:
			{
				UNHOOK_SSDT64 uhssdt64 = { 0 };
				memcpy( &uhssdt64 ,
					pInOutBuffer , sizeof( UNHOOK_SSDT64 ) );
				_UnhookSSDT( &uhssdt64 );
				Status = STATUS_SUCCESS;
				break;
			}
		default:
			_ASSERT( FALSE );
	}

	_pIrp->IoStatus.Status = Status;
	_pIrp->IoStatus.Information = uInformation;
	IoCompleteRequest( _pIrp , IO_NO_INCREMENT );
	return	Status;
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
该函数在SSDT中查找目标函数地址
参数:
ULONG id	目标函数在SSDT中的id
返回值:	ULONGLONG
*/
ULONGLONG	_GetSSDTFuncAddr(
	IN	ULONG	_id
)
{
	LONG	dwFuncOffset = 0;	//注意偏移是有符号的
	PULONG	ServiceTableBase = NULL;

	ServiceTableBase =
		(PULONG)KeServiceDescriptorTable->ServiceTableBase;
	dwFuncOffset = ServiceTableBase[_id];
	dwFuncOffset = dwFuncOffset >> 4;

	return	dwFuncOffset + (ULONGLONG)ServiceTableBase;
	/*ULONGLONG ret = 0;

	if (scfn == NULL)
		Initxxxx();
	ret = scfn( _id , (ULONGLONG)KeServiceDescriptorTable );
	return ret;*/
}


/*
该函数根据指定的地址恢复ssdt的hook
*/
VOID	_UnhookSSDT(
	IN	PUNHOOK_SSDT64	_pUnhookSSDT
)
{
	KIRQL	Irql;
	ULONG	FuncOffset;
	PULONG	ServiceTableBase = NULL;

	FuncOffset = _GetOffsetAddress( _pUnhookSSDT->Address );
	ServiceTableBase = (PULONG)
		KeServiceDescriptorTable->ServiceTableBase;
	Irql = WPOFFx64();
	ServiceTableBase[_pUnhookSSDT->id] = FuncOffset;
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


VOID Initxxxx()
{
	UCHAR strShellCode[36] = "\x48\x8B\xC1\x4C\x8D\x12\x8B\xF8\xC1\xEF\x07\x83\xE7\x20\x4E\x8B\x14\x17\x4D\x63\x1C\x82\x49\x8B\xC3\x49\xC1\xFB\x04\x4D\x03\xD3\x49\x8B\xC2\xC3";
	/*
	mov rax, rcx ;rcx=index
	lea r10,[rdx] ;rdx=ssdt
	mov edi,eax
	shr edi,7
	and edi,20h
	mov r10, qword ptr [r10+rdi]
	movsxd r11,dword ptr [r10+rax*4]
	mov rax,r11
	sar r11,4
	add r10,r11
	mov rax,r10
	ret
	*/
	scfn = ExAllocatePool( NonPagedPool , 36 );
	memcpy( scfn , strShellCode , 36 );
}
