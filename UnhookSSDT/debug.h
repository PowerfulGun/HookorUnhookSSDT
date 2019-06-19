#ifndef DEBUG_H
#define	DEBUG_H


//
// debug的优先级
//
#define DL_EXTRA_LOUD       20
#define DL_VERY_LOUD        10
#define DL_LOUD             8
#define DL_INFO             6
#define DL_TRACE            5
#define DL_WARN             4
#define DL_ERROR            2
#define DL_FATAL            0

#define	DebugLevel	DL_INFO

#if DBG




#define DEBUG(lev, ...)                                                \
        {                                                               \
            if ((lev) <= DebugLevel)                              \
            {                                                           \
                 DbgPrint(__VA_ARGS__);									\
            }                                                           \
        }

#define DEBUGDUMP(lev, pBuf, Len)                                      \
        {                                                               \
            if ((lev) <= DebugLevel)                              \
            {                                                           \
                _DbgPrintHexDump((PUCHAR)(pBuf), (ULONG)(Len));          \
            }                                                           \
        }

#define _ASSERT(exp)                                              \
        {                                                               \
            if (!(exp))                                                 \
            {                                                           \
                DbgPrint("Filter: assert " #exp " failed in"            \
                    " file %s, line %d\n", __FILE__, __LINE__);         \
                DbgBreakPoint();                                        \
            }                                                           \
        }

#endif	DBG



//用于内存管理的宏定义
#if DBG
#define	ALLOC_MEM(_NdisHandle,_Size)	\
	_AllocateMemory(						\
		_Size ,								\
		FILENUMBER ,						\
		__LINE__ );

#define	FREE_MEM(_pBuffer)	\
	_FreeMemory(_pBuffer);

#define	CHECK_MEMORY()	\
	_CheckMemory();

#else
#define	ALLOC_MEM(_NdisHandle,_Size)	\
	NdisAllocateMemoryWithTagPriority(		\
			_NdisHandle,					\
			_Size,							\
			'hqsb',							\
			NormalPoolPriority );
		
#define	FREE_MEM(_pBuffer)	\
	NdisFreeMemory(_pBuffer,0,0);

#define	CHECK_MEMORY()

#endif // DBG


#if DBG

#define MEMORY_SIGNATURE    (ULONG)'qnmd'

//
// The _ALLOCATE_INFORMATION structure 
//	stores all info about one allocation
//	内存分配信息结构体,用来管理驱动中申请的内存
typedef struct _ALLOCATE_INFORMATION {

	ULONG							Signature;
	struct _ALLOCATE_INFORMATION   *Next;
	struct _ALLOCATE_INFORMATION   *Prev;
	ULONG							FileNumber;
	ULONG							LineNumber;
	ULONG							Size;
//	NDIS_HANDLE						OwnerHandle;
	union
	{
		ULONGLONG               Alignment;
		UCHAR                   UserData;
	};

}ALLOCATE_INFORMATION , *PALLOCATE_INFORMATION;



//#if DBG_SPIN_LOCK
//#define FILTER_INIT_LOCK(_pLock)                          \
//    filterAllocateSpinLock(_pLock, __FILENUMBER, __LINE__)
//
//#define FILTER_FREE_LOCK(_pLock)       filterFreeSpinLock(_pLock)
//
//
//#define FILTER_ACQUIRE_LOCK(_pLock, DispatchLevel)  \
//    filterAcquireSpinLock(_pLock, __FILENUMBER, __LINE__, DisaptchLevel)
//
//#define FILTER_RELEASE_LOCK(_pLock, DispatchLevel)      \
//    filterReleaseSpinLock(_pLock, __FILENUMBER, __LINE__, DispatchLevel)
//
//#else
//#define FILTER_INIT_LOCK(_pLock)      NdisAllocateSpinLock(_pLock)
//
//#define FILTER_FREE_LOCK(_pLock)      NdisFreeSpinLock(_pLock)
//
//#define FILTER_ACQUIRE_LOCK(_pLock, DispatchLevel)              \
//    {                                                           \
//        if (DispatchLevel)                                      \
//        {                                                       \
//            NdisDprAcquireSpinLock(_pLock);                     \
//        }                                                       \
//        else                                                    \
//        {                                                       \
//            NdisAcquireSpinLock(_pLock);                        \
//        }                                                       \
//    }
//
//#define FILTER_RELEASE_LOCK(_pLock, DispatchLevel)              \
//    {                                                           \
//        if (DispatchLevel)                                      \
//        {                                                       \
//            NdisDprReleaseSpinLock(_pLock);                     \
//        }                                                       \
//        else                                                    \
//        {                                                       \
//            NdisReleaseSpinLock(_pLock);                        \
//        }                                                       \
//    }
//#endif //DBG_SPIN_LOCK


//
//	函数声明
//
PVOID	_AllocateMemory(
//	IN	NDIS_HANDLE	_NdisHandle ,
	IN	ULONG	_Size ,
	IN	ULONG	_FileNumber ,
	IN	ULONG	_LineNumber
);

VOID	_FreeMemory(
	IN	PVOID	_pBuffer
);

VOID	_CheckMemory();

VOID	_DbgPrintHexDump(
	IN    PUCHAR            pBuffer ,
	IN    ULONG            Length
);



#endif // DBG


#endif // !DEBUG_H
