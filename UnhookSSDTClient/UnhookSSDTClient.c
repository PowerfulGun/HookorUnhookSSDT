// UnhookSSDTClient.cpp : 定义控制台应用程序的入口点。
//
#include "precomp.h"


ULONGLONG	NtOSBase = 0;	//内核文件在内核中的加载地址
ULONGLONG	NtOSImageBase = 0;	//内核文件在PE32+结构体中的映像基址
ULONGLONG	NtOSInProcess = 0;//将内核文件加载到本进程的地址
CHAR NtOSName[260] = { 0 };
ULONGLONG	KiServiceTable = 0;
ULONG	SSDTFuncCnt = 0;
HANDLE	g_hControlDevice;	//驱动设备
HANDLE	g_hEvent;

int main()
{
	//用事件对象保证只有一个客户端在运行
	g_hEvent = OpenEvent(
		EVENT_ALL_ACCESS ,
		FALSE ,
		L"PowerfulGun_UnhookSSDTClient" );
	if (g_hEvent)
	{
		printf( "The client is running !\n" );
		CloseHandle( g_hEvent );
		return	0;
	}

	g_hEvent = CreateEvent(
		NULL ,
		FALSE ,
		FALSE ,
		L"PowerfulGun_UnhookSSDTClient" );
	if (g_hEvent == NULL)
	{
		printf( "Fail to create event !\n" );
		return	0;
	}

	//准备工作
	//打开驱动设备
	g_hControlDevice = CreateFileA(
		"\\\\.\\PowerfulGun_UnhookSSDT" ,
		GENERIC_WRITE | GENERIC_READ ,
		FILE_SHARE_READ ,
		NULL ,
		OPEN_EXISTING ,
		FILE_ATTRIBUTE_NORMAL ,
		NULL );
	if (g_hControlDevice == INVALID_HANDLE_VALUE)
	{
		printf( "Fail to get control device !\n" );
		return	0;
	}

	//获得ZwQuerySystemInformation函数地址
	ZwQuerySystemInformation = (ZWQUERYSYSTEMINFORMATION)
		GetProcAddress(
		GetModuleHandleA( "ntdll.dll" ) ,
		"ZwQuerySystemInformation" );

	_GetNtOsBase();
	_GetNtOSImageBase();
	_GetKiServiceTable();
	printf( "\nPress [ENTER] to continue...\n" );
	getchar();
	_PrintAllSSDTFunc();
	do
	{
		WCHAR	CmdBuffer[256];
		ULONG	StringPos = 0;

		printf( "\nInput index to unhook or press [ENTER] to end\n" );
		//获得命令字符
		while (TRUE)
		{
			CmdBuffer[StringPos] = getwchar();

			if (CmdBuffer[StringPos] == L'\n')
				break;
			if (StringPos == sizeof( CmdBuffer ) / sizeof( WCHAR ))
			{
				printf( "Too long !\n" );
				//清空输入缓冲区
				while (getwchar() != L'\n') 
				{}

				StringPos = 0;
				continue;
			}
			StringPos++;
		}
		StringPos = 0;

		//回车键退出
		if (CmdBuffer[0] == L'\n')
			break;

		//获得输入的index
		ULONG	Index = 
			wcstoul( CmdBuffer , NULL , 16 );
		if (Index > SSDTFuncCnt - 1||Index==0)
		{
			printf( "Error index 0x%x !\n" , Index );
			//goto	INPUT;
			break;
		}
		//恢复ssdt
		_UnhookSSDT( Index );

	} while (TRUE);

    return 0;
}


/*
该函数获得内核文件在内核中的加载地址和内核文件名
*/
VOID	_GetNtOsBase()
{
	ULONG	ReturnLength = 0 , BufferLength = 0x5000;
	PVOID	pBuffer = NULL;
	PSYSTEM_MODULE_INFORMATION	pSystemModuleInformation;
	NTSTATUS	Status;

	//分配内存
	pBuffer = malloc( BufferLength );
	if (pBuffer == NULL)
	{
		printf( "_GetNtOsBase: malloc error\n" );
		return;
	}

	//查询模块信息
	Status = ZwQuerySystemInformation(
		11 ,	//SystemModuleInformation
		pBuffer ,
		BufferLength ,
		&ReturnLength );
	if (Status == STATUS_INFO_LENGTH_MISMATCH)
	{
		free( pBuffer );
		pBuffer = malloc( ReturnLength );
		BufferLength = ReturnLength;
		if (pBuffer == NULL)
		{
			printf( "_GetNtOsBase: malloc error\n" );
			return;
		}
	}

	Status = ZwQuerySystemInformation(
		11 ,	//SystemModuleInformation
		pBuffer ,
		BufferLength ,
		&ReturnLength );
	if (!NT_SUCCESS( Status ))
	{
		printf( "_GetNtOsBase: ZwQuerySystemInformation fail, Status=%x\n" ,
			Status );
		return;
	}

	pSystemModuleInformation =
		(PSYSTEM_MODULE_INFORMATION)pBuffer;

	//保存内核文件名
	strcpy_s( NtOSName , 260 ,
		"C:\\Windows\\system32\\" );
	strcat_s( NtOSName ,260,
		pSystemModuleInformation->Module[0].ImageName
		+ pSystemModuleInformation->Module[0].ModuleNameOffset );
	NtOSBase = (ULONGLONG)pSystemModuleInformation->Module[0].Base;
	printf( "NTOSKRNL base: %llx\n" , NtOSBase );
	printf( "NTOSKRNL name: %s\n" , NtOSName );

	free( pBuffer );
}


/*
该函数获得内核文件在PE32+结构体中的映像基址
*/
VOID	_GetNtOSImageBase()
{
	PIMAGE_DOS_HEADER	pDosHeader;
	PIMAGE_NT_HEADERS64	pHeader64;
	PUCHAR	pBuffer;
	DWORD	dwReadWrite;
	HANDLE	hFile;
	WIN32_FIND_DATAA	FileInfo = { 0 };

	hFile = FindFirstFileA(
		NtOSName , &FileInfo );
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf( "_GetNtOSImageBase: FindFirstFileA fail !\n" );
		return;
	}
	FindClose( hFile );

	hFile = CreateFileA(
		NtOSName ,
		GENERIC_READ ,
		FILE_SHARE_READ ,
		0 ,
		OPEN_EXISTING ,
		0 , 0 );
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf( "_GetNtOSImageBase: CreateFileA fail !\n" );
		return;
	}

	pBuffer = (PUCHAR)malloc( FileInfo.nFileSizeLow );
	SetFilePointer( hFile , 0 , 0 , FILE_BEGIN );
	ReadFile( hFile ,
		pBuffer , FileInfo.nFileSizeLow ,
		&dwReadWrite , 0 );
	CloseHandle( hFile );

	pDosHeader = (PIMAGE_DOS_HEADER)pBuffer;
	pHeader64 = (PIMAGE_NT_HEADERS64)
		(pBuffer + pDosHeader->e_lfanew);
	
	NtOSImageBase = pHeader64->OptionalHeader.ImageBase;
	printf( "NtOSImageBase=%llx\n" , NtOSImageBase );

	free( pBuffer );
}


VOID	_GetKiServiceTable()
{
	DWORD	dwRet=0;

	if (!DeviceIoControl(
		g_hControlDevice ,
		IOCTL_GetKiSrvTab ,
		NULL , 0 ,
		&KiServiceTable , 8 ,
		&dwRet ,
		NULL ))
	{
		printf( "_GetKiServiceTable: Fail !\n" );
	}
	else
	{
		printf( "KiServiceTable=%llx\n" , KiServiceTable );
	}
}


/*
该函数打印SSDT函数地址和函数名
*/
VOID	_PrintAllSSDTFunc()
{
	WIN32_FIND_DATAA	FileInfo = { 0 };
	DWORD	dwFileLen,FuncStart,FuncEnd;
	HANDLE	hFile;
	PCHAR NtdllTXT = NULL;

	//将内核文件拷贝到别处
	CopyFile(
		L"c:\\windows\\system32\\ntdll.dll" ,
		L"c:\\ntdll.txt" , 
		0 );

	hFile = FindFirstFileA( "c:\\ntdll.txt" , &FileInfo );
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf( "_PrintAllSSDTFunc.FindFirstFileA: fail !\n" );
		return;
	}
	FindClose( hFile );
	dwFileLen = FileInfo.nFileSizeLow;

	char func_start[] = "NtAcceptConnectPort" , 
		func_end[] = "NtYieldExecution"; //每个函数名之间隔着\0

	char *funs = (char *)malloc( strlen( func_start ) );
	memcpy( funs , func_start , strlen( func_start ) );

	char *fune = (char *)malloc( strlen( func_end ) );
	memcpy( fune , func_end , strlen( func_end ) );

	DWORD	dwReadWrite;
	hFile = CreateFileA( 
		"c:\\ntdll.txt" ,
		GENERIC_READ | GENERIC_WRITE , 
		FILE_SHARE_READ | FILE_SHARE_WRITE , 
		0 , 
		OPEN_EXISTING , 
		0 , 0 );
	if (hFile != INVALID_HANDLE_VALUE)
	{
		NtdllTXT = (PCHAR)malloc( dwFileLen );
		SetFilePointer( hFile , 0 , 0 , FILE_BEGIN );
		ReadFile( hFile ,
			NtdllTXT ,
			dwFileLen ,
			&dwReadWrite , 0 );
		CloseHandle( hFile );
	}
	else
	{
		printf( "_PrintAllSSDTFunc.CreateFileA: Fail flie:c:\\ntdll.txt" );
		DeleteFileA( "c:\\ntdll.txt" );
		return;
	}

	//找到函数名起始和结束地址
	for (ULONG i = 0; i < dwFileLen; i++)
	{
		if (memcmp( NtdllTXT + i , funs , strlen( func_start )) == 0 )
			FuncStart = i;
		if (memcmp( NtdllTXT + i , fune , strlen( func_end ) ) == 0)
		{
			FuncEnd = i;
			break;
		}
	}

	NtdllTXT += FuncStart;

	printf( "ID\t当前地址\t\t原始地址\t\t函数名\n" );
	ULONG	PauseCnt = 0,FuncCnt=0;
	while (TRUE)
	{
		DWORD	Index;
		ULONGLONG	FuncOriAddr,FuncCurAddr;
		DWORD	Ret;

		//获得函数编号
		Index = *(DWORD*)((PUCHAR)GetProcAddress(
			LoadLibrary( L"ntdll.dll" ) ,
			NtdllTXT ) + 4);
		if (Index > 1000)
		{
			//当获得ZwQuerySystemTime函数的index时会有问题
			/*
			0:000> u ZwQuerySystemTime
			ntdll!ZwQuerySystemTime:
			00000000`77b20450 e91b62fdff      jmp     ntdll!RtlQuerySystemTime (00000000`77af6670)
			00000000`77b20455 6666660f1f840000000000 nop word ptr [rax+rax]
			*/
			/*
			nt!ZwQuerySystemTime:
			fffff800`01673fa0 488bc4          mov     rax,rsp
			fffff800`01673fa3 fa              cli
			fffff800`01673fa4 4883ec10        sub     rsp,10h
			fffff800`01673fa8 50              push    rax
			fffff800`01673fa9 9c              pushfq
			fffff800`01673faa 6a10            push    10h
			fffff800`01673fac 488d053d270000  lea     rax,[nt!KiServiceLinkage (fffff800`016766f0)]
			fffff800`01673fb3 50              push    rax
			fffff800`01673fb4 b857000000      mov     eax,57h
			fffff800`01673fb9 e9825e0000      jmp     nt!KiServiceInternal (fffff800`01679e40)
			fffff800`01673fbe 6690            xchg    ax,ax
			*/
			//不同的系统，不同的编号，
			//由于目前只有WIN7 X64，所以这里直接硬编码了
			Index = 0x57;
		}
		FuncOriAddr = _GetFuncOriginalAddress( Index );
		//向驱动获取当前内核函数地址
		DeviceIoControl(
			g_hControlDevice ,
			IOCTL_GetFuncAddr ,
			&Index , 4 ,
			&FuncCurAddr , 8 ,
			&Ret , NULL );
		if (FuncCurAddr != FuncOriAddr)
			printf( "!!! " );
		printf( "0x%x\t%llx\t%llx\t%s\n" ,
			Index , FuncCurAddr , FuncOriAddr , NtdllTXT );

		FuncCnt++;

		//判断是否要退出循环
		if (strcmp( NtdllTXT , func_end ) == 0)
		{
			printf( "\nTotal of SSDT function: %d\n" , FuncCnt );
			SSDTFuncCnt = FuncCnt;
			break;
		}

		NtdllTXT += strlen( NtdllTXT ) + 1;
		PauseCnt++;
		if (PauseCnt == 101)
		{
			printf( "\nPress [ENTER] to continue...\n" );
			getchar();
			PauseCnt = 0;
		}
	}//end while
	//删除拷贝的临时文件
	DeleteFileA( "c:\\ntdll.txt" );
}


/*
该函数通过Index获得在内核文件中的函数地址
*/
ULONGLONG	_GetFuncOriginalAddress(
	IN	DWORD	_Index
)
{
	if (NtOSInProcess == 0)
		NtOSInProcess = (ULONGLONG)
		LoadLibraryExA( NtOSName ,//"C:\\Windows\\system32\\ntkrnlmp.exe"
		0 , DONT_RESOLVE_DLL_REFERENCES );

	ULONGLONG	RVA = KiServiceTable - NtOSBase;
	ULONGLONG	Temp = *(PULONGLONG)
		(NtOSInProcess + RVA + 8 * (ULONGLONG)_Index);
	//temp值是函数相对于imagebase的地址
	//IMAGE_OPTIONAL_HEADER64.ImageBase=0x140000000（这个值基本是固定的）
	//真正的函数地址应该相对于NtOSBase,如下操作
	return	Temp - NtOSImageBase + NtOSBase;
}


/*
该函数还原指定index的内核函数地址
*/
VOID	_UnhookSSDT(
	IN	DWORD	_Index
)
{
	ULONGLONG	FuncOriAddr = 0;
	UNHOOK_SSDT64	data = { 0 };
	DWORD	Ret;

	FuncOriAddr = _GetFuncOriginalAddress( _Index );
	data.Address = FuncOriAddr;
	data.id = _Index;

	DeviceIoControl(
		g_hControlDevice ,
		IOCTL_ClrSSDTHOOK ,
		&data , sizeof( data ) ,
		NULL , 0 ,
		&Ret , NULL );
}