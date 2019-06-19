// UnhookSSDTClient.cpp : �������̨Ӧ�ó������ڵ㡣
//
#include "precomp.h"


ULONGLONG	NtOSBase = 0;	//�ں��ļ����ں��еļ��ص�ַ
ULONGLONG	NtOSImageBase = 0;	//�ں��ļ���PE32+�ṹ���е�ӳ���ַ
ULONGLONG	NtOSInProcess = 0;//���ں��ļ����ص������̵ĵ�ַ
CHAR NtOSName[260] = { 0 };
ULONGLONG	KiServiceTable = 0;
ULONG	SSDTFuncCnt = 0;
HANDLE	g_hControlDevice;	//�����豸
HANDLE	g_hEvent;

int main()
{
	//���¼�����ֻ֤��һ���ͻ���������
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

	//׼������
	//�������豸
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

	//���ZwQuerySystemInformation������ַ
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
		//��������ַ�
		while (TRUE)
		{
			CmdBuffer[StringPos] = getwchar();

			if (CmdBuffer[StringPos] == L'\n')
				break;
			if (StringPos == sizeof( CmdBuffer ) / sizeof( WCHAR ))
			{
				printf( "Too long !\n" );
				//������뻺����
				while (getwchar() != L'\n') 
				{}

				StringPos = 0;
				continue;
			}
			StringPos++;
		}
		StringPos = 0;

		//�س����˳�
		if (CmdBuffer[0] == L'\n')
			break;

		//��������index
		ULONG	Index = 
			wcstoul( CmdBuffer , NULL , 16 );
		if (Index > SSDTFuncCnt - 1||Index==0)
		{
			printf( "Error index 0x%x !\n" , Index );
			//goto	INPUT;
			break;
		}
		//�ָ�ssdt
		_UnhookSSDT( Index );

	} while (TRUE);

    return 0;
}


/*
�ú�������ں��ļ����ں��еļ��ص�ַ���ں��ļ���
*/
VOID	_GetNtOsBase()
{
	ULONG	ReturnLength = 0 , BufferLength = 0x5000;
	PVOID	pBuffer = NULL;
	PSYSTEM_MODULE_INFORMATION	pSystemModuleInformation;
	NTSTATUS	Status;

	//�����ڴ�
	pBuffer = malloc( BufferLength );
	if (pBuffer == NULL)
	{
		printf( "_GetNtOsBase: malloc error\n" );
		return;
	}

	//��ѯģ����Ϣ
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

	//�����ں��ļ���
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
�ú�������ں��ļ���PE32+�ṹ���е�ӳ���ַ
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
�ú�����ӡSSDT������ַ�ͺ�����
*/
VOID	_PrintAllSSDTFunc()
{
	WIN32_FIND_DATAA	FileInfo = { 0 };
	DWORD	dwFileLen,FuncStart,FuncEnd;
	HANDLE	hFile;
	PCHAR NtdllTXT = NULL;

	//���ں��ļ���������
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
		func_end[] = "NtYieldExecution"; //ÿ��������֮�����\0

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

	//�ҵ���������ʼ�ͽ�����ַ
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

	printf( "ID\t��ǰ��ַ\t\tԭʼ��ַ\t\t������\n" );
	ULONG	PauseCnt = 0,FuncCnt=0;
	while (TRUE)
	{
		DWORD	Index;
		ULONGLONG	FuncOriAddr,FuncCurAddr;
		DWORD	Ret;

		//��ú������
		Index = *(DWORD*)((PUCHAR)GetProcAddress(
			LoadLibrary( L"ntdll.dll" ) ,
			NtdllTXT ) + 4);
		if (Index > 1000)
		{
			//�����ZwQuerySystemTime������indexʱ��������
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
			//��ͬ��ϵͳ����ͬ�ı�ţ�
			//����Ŀǰֻ��WIN7 X64����������ֱ��Ӳ������
			Index = 0x57;
		}
		FuncOriAddr = _GetFuncOriginalAddress( Index );
		//��������ȡ��ǰ�ں˺�����ַ
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

		//�ж��Ƿ�Ҫ�˳�ѭ��
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
	//ɾ����������ʱ�ļ�
	DeleteFileA( "c:\\ntdll.txt" );
}


/*
�ú���ͨ��Index������ں��ļ��еĺ�����ַ
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
	//tempֵ�Ǻ��������imagebase�ĵ�ַ
	//IMAGE_OPTIONAL_HEADER64.ImageBase=0x140000000�����ֵ�����ǹ̶��ģ�
	//�����ĺ�����ַӦ�������NtOSBase,���²���
	return	Temp - NtOSImageBase + NtOSBase;
}


/*
�ú�����ԭָ��index���ں˺�����ַ
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