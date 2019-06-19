#include	"precomp.h"


#if DBG
//
//	�ڴ����Ҫ�õ���һЩȫ�ֱ���
//

KSPIN_LOCK	gMemoryLock;	//ͬ���õ�������
BOOLEAN		gbLockInited = FALSE;//�������Ƿ��ʼ������

PALLOCATE_INFORMATION	gpMemoryHead = NULL;//ָ���ڴ������Ϣ˫����ͷ��
PALLOCATE_INFORMATION	gpMemoryTail = NULL;//ָ���ڴ������Ϣ˫����β��
ULONG	gAllocInforCount = 0;	//��¼����ʹ���е��ڴ�������,����ʱ��1,�ͷ�ʱ��1

/*
�ú������������ڴ�,˳����õ����ڴ����"ͷ"���ڹ���
����:
Size			Ҫ����Ĵ�С
FileNumber		�����ڴ�Ĵ���������ĸ�Դ�ļ���(��¼��ͷ�б��ڲ����ڴ�й©)
LineNumber		�����ڴ�Ĵ��������Դ�ļ�������(��¼��ͷ�б��ڲ����ڴ�й©)
����ֵ:
	NULL	����ʧ��
	PVOID	ָ������õ���Size��С���ڴ�
*/
PVOID	_AllocateMemory(
	IN	ULONG	_Size ,
	IN	ULONG	_FileNumber ,
	IN	ULONG	_LineNumber
)
{
	KLOCK_QUEUE_HANDLE LockHandle;
	PVOID	pBuffer;
	PALLOCATE_INFORMATION	pAllocInfor;

	if (!gbLockInited)
	{
		//����ڴ���������û�г�ʼ�������ȳ�ʼ��������
		KeInitializeSpinLock( &gMemoryLock );
		gbLockInited = TRUE;
	}

	//�����Ҫ������ڴ���Ϸ�����Ϣ�ṹ��Ĵ�С�Ƿ񳬹�ULONG����
	if (
		(_Size + (ULONG)sizeof( ALLOCATE_INFORMATION ))
		< _Size)
	{
		KdPrint( ("_AllocateMemory: Overflow!\n\
		At file:%d, line:%d, size:%d\n" ,
			_FileNumber , _LineNumber , _Size) );

		return NULL;
	}

	pAllocInfor =
		ExAllocatePoolWithTagPriority(
		NonPagedPool ,
		_Size + sizeof( ALLOCATE_INFORMATION ) ,
		(ULONG)'hqsb' ,
		NormalPoolPriority );

	/*pAllocInfor =
		NdisAllocateMemoryWithTagPriority(
		_NdisHandle ,
		_Size + sizeof( ALLOCATE_INFORMATION ) ,
		(ULONG)'hqsb' ,
		NormalPoolPriority );*/
	if (pAllocInfor == NULL)
	{
		KdPrint( ("_AllocateMemory: Fail to allocate memory,\n\
			at file:%d, line:%d, size:%d\n" ,
			_FileNumber , _LineNumber , _Size) );

		return	NULL;
	}

	pBuffer = (PVOID)&pAllocInfor->UserData;
	//NdisZeroMemory( pBuffer , _Size );
	pAllocInfor->Signature = MEMORY_SIGNATURE;
	pAllocInfor->FileNumber = _FileNumber;
	pAllocInfor->LineNumber = _LineNumber;
	pAllocInfor->Size = _Size;
//	pAllocInfor->OwnerHandle = _NdisHandle;
	pAllocInfor->Next = NULL;

	//������ڵ�����ڴ������Ϣ˫����β��
	//����Ĳ�����Ҫ������ͬ��
	KeAcquireInStackQueuedSpinLock(
		&gMemoryLock , &LockHandle );

	pAllocInfor->Prev = gpMemoryTail;
	//�ж�һ���Ƿ�˫����Ϊ��
	if (gpMemoryTail == NULL)
	{
		//������
		gpMemoryHead = gpMemoryTail = pAllocInfor;
	}
	else
	{
		//��Ϊ��
		gpMemoryTail->Next = pAllocInfor;
	}
	gpMemoryTail = pAllocInfor;
	gAllocInforCount++;

	KeReleaseInStackQueuedSpinLock(
		&LockHandle );

	KdPrint( ("_AllocateMemory: Success to allocate memory,\n\
	at file:%d, line:%d, size:%d \n" ,
		_FileNumber , _LineNumber , _Size ) );

	return	pBuffer;
}


/*
�ú����ͷ��ڴ�
*/
VOID	_FreeMemory(
	IN	PVOID	_pBuffer
)
{
	KLOCK_QUEUE_HANDLE LockHandle;
	PALLOCATE_INFORMATION	pAllocateInfor;

	KeAcquireInStackQueuedSpinLock(
		&gMemoryLock , &LockHandle );

	pAllocateInfor =
		CONTAINING_RECORD( _pBuffer , ALLOCATE_INFORMATION , UserData );
	if (pAllocateInfor->Signature != MEMORY_SIGNATURE)
	{
		KdPrint( ("_FreeMemory: Unknown buffer:%p\n" , _pBuffer) );
		KeReleaseInStackQueuedSpinLock(
			&LockHandle );
#if DBG
		DbgBreakPoint();
#endif
		return;
	}

	//�����ڴ��ͷű��
	pAllocateInfor->Signature = 'DEAD';

	//������ڵ���ڴ������Ϣ��˫�����ж���
	if (pAllocateInfor->Prev != NULL)
		pAllocateInfor->Prev->Next = pAllocateInfor->Next;
	else
	{
		//����ڵ���ͷ�ڵ�
		gpMemoryHead = pAllocateInfor->Next;
	}
	if (pAllocateInfor->Next != NULL)
		pAllocateInfor->Next->Prev = pAllocateInfor->Prev;
	else
	{
		//����ڵ���β�ڵ�
		gpMemoryTail = pAllocateInfor->Prev;
	}
	gAllocInforCount--;

	KeReleaseInStackQueuedSpinLock(
		&LockHandle );

	//�ͷ��ڴ�
	ExFreePool( pAllocateInfor );
}


/*
�ú�������Ƿ���û���ͷŵ��ڴ�,��λ�����ڴ�Ĵ���λ��Ȼ��һ���ͷ�
*/
VOID	_CheckMemory()
{
	if (!gbLockInited)
		return;

	if (gAllocInforCount == 0)
	{
		KdPrint( ("_CheckMemory: All memory freed!\n") );
		return;
	}

	PALLOCATE_INFORMATION	pAllocateInfor;
	while (gpMemoryHead != NULL)
	{
		pAllocateInfor = gpMemoryHead;
		KdPrint( ("_CheckMemory: Unfreed memory at\n\
		file:%d, line:%d, size:%d\n" ,
			pAllocateInfor->FileNumber ,
			pAllocateInfor->LineNumber ,
			pAllocateInfor->Size) );
		_FreeMemory( &pAllocateInfor->UserData );
	}
}



VOID
_DbgPrintHexDump(
	IN    PUCHAR            pBuffer ,
	IN    ULONG            Length
)
{
	ULONG        i;

	if (Length > 256)
	{
		Length = 256;
	}

	for (i = 0; i < Length; i++)
	{
		//
		//  Check if we are at the end of a line
		//
		if ((i > 0) && ((i & 0xf) == 0))
		{
			DbgPrint( "\n" );
		}

		//
		//  Print addr if we are at start of a new line
		//
		if ((i & 0xf) == 0)
		{
			DbgPrint( "%08p " , pBuffer );
		}

		DbgPrint( " %02x" , *pBuffer++ );
	}

	//
	//  Terminate the last line.
	//
	if (Length > 0)
	{
		DbgPrint( "\n" );
	}
}
#endif // DBG
