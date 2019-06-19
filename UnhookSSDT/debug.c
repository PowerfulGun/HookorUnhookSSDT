#include	"precomp.h"


#if DBG
//
//	内存管理要用到的一些全局变量
//

KSPIN_LOCK	gMemoryLock;	//同步用的自旋锁
BOOLEAN		gbLockInited = FALSE;//自旋锁是否初始化过了

PALLOCATE_INFORMATION	gpMemoryHead = NULL;//指向内存分配信息双链表头部
PALLOCATE_INFORMATION	gpMemoryTail = NULL;//指向内存分配信息双链表尾部
ULONG	gAllocInforCount = 0;	//记录正在使用中的内存块的数量,申请时加1,释放时减1

/*
该函数用来申请内存,顺便给得到的内存加上"头"便于管理
参数:
Size			要申请的大小
FileNumber		申请内存的代码出现在哪个源文件中(记录在头中便于查找内存泄漏)
LineNumber		申请内存的代码出现在源文件的行数(记录在头中便于查找内存泄漏)
返回值:
	NULL	申请失败
	PVOID	指向申请得到的Size大小的内存
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
		//如果内存自旋锁还没有初始化过就先初始化自旋锁
		KeInitializeSpinLock( &gMemoryLock );
		gbLockInited = TRUE;
	}

	//检查需要分配的内存加上分配信息结构体的大小是否超过ULONG上限
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

	//将这个节点放入内存分配信息双链表尾部
	//下面的操作需要自旋锁同步
	KeAcquireInStackQueuedSpinLock(
		&gMemoryLock , &LockHandle );

	pAllocInfor->Prev = gpMemoryTail;
	//判断一下是否双链表为空
	if (gpMemoryTail == NULL)
	{
		//空链表
		gpMemoryHead = gpMemoryTail = pAllocInfor;
	}
	else
	{
		//不为空
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
该函数释放内存
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

	//设置内存释放标记
	pAllocateInfor->Signature = 'DEAD';

	//将这个节点从内存分配信息的双链表中断链
	if (pAllocateInfor->Prev != NULL)
		pAllocateInfor->Prev->Next = pAllocateInfor->Next;
	else
	{
		//这个节点是头节点
		gpMemoryHead = pAllocateInfor->Next;
	}
	if (pAllocateInfor->Next != NULL)
		pAllocateInfor->Next->Prev = pAllocateInfor->Prev;
	else
	{
		//这个节点是尾节点
		gpMemoryTail = pAllocateInfor->Prev;
	}
	gAllocInforCount--;

	KeReleaseInStackQueuedSpinLock(
		&LockHandle );

	//释放内存
	ExFreePool( pAllocateInfor );
}


/*
该函数检查是否有没有释放的内存,定位申请内存的代码位置然后一并释放
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
