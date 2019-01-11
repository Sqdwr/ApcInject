#include "DefineStruct.h"
#include "APC.h"

PVOID GetProcAddress(WCHAR *wProcName)
{
	UNICODE_STRING uProcName = { 0 };

	RtlInitUnicodeString(&uProcName, wProcName);

	return MmGetSystemRoutineAddress(&uProcName);
}

HANDLE OpenProcess(HANDLE ProcessId)
{
	HANDLE ProcessHandle = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	CLIENT_ID ClientId = { 0 };

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	do
	{
		ClientId.UniqueProcess = ProcessId;
		InitializeObjectAttributes(&ObjectAttributes, 0, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);

		Status = ZwOpenProcess(&ProcessHandle, PROCESS_ALL_ACCESS, &ObjectAttributes, &ClientId);
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("调用ZwOpenProcess失败！错误码是：%x！\n", Status));
			break;
		}

	} while (FALSE);

	return ProcessHandle;
}

BOOLEAN IsPE(ULONG_PTR ModuleBase)
{
	PIMAGE_DOS_HEADER DosHeader = NULL;
	PIMAGE_NT_HEADERS NtHeader = NULL;

	BOOLEAN RetValue = FALSE;

	do
	{
		DosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
		if (DosHeader == NULL)
		{
			KdPrint(("基址为空！\n"));
			break;
		}

		if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			KdPrint(("DosHeader->e_magic不正确！\n"));
			break;
		}

		NtHeader = (IMAGE_NT_HEADERS *)(ModuleBase + DosHeader->e_lfanew);
		if (NtHeader->Signature != IMAGE_NT_SIGNATURE)
		{
			KdPrint(("NtHeader->Signature不正确！\n"));
			break;
		}

		RetValue = TRUE;

	} while (FALSE);

	return RetValue;
}

PIMAGE_NT_HEADERS GetNtHeader(ULONG_PTR ModuleBase)
{
	PIMAGE_NT_HEADERS NtHeader = NULL;

	do
	{
		if (IsPE(ModuleBase) == FALSE)
		{
			KdPrint(("文件不是PE文件！\n"));
			break;
		}

		NtHeader = (IMAGE_NT_HEADERS *)(ModuleBase + ((PIMAGE_DOS_HEADER)ModuleBase)->e_lfanew);

	} while (FALSE);

	return NtHeader;
}

PVOID GetDirectory(ULONG_PTR ModuleBase,ULONG DirectoryIndex)
{
	PIMAGE_NT_HEADERS NtHeader = NULL;
	PVOID RetDirectory = NULL;

	do
	{
		NtHeader = GetNtHeader(ModuleBase);
		if (NtHeader == NULL)
		{
			KdPrint(("获取NtHeader失败！\n"));
			break;
		}

		if (NtHeader->OptionalHeader.DataDirectory[DirectoryIndex].Size == 0)
		{
			KdPrint(("想要获取的DataDirectory大小为空！\n"));
			break;
		}

		RetDirectory = (PVOID)(ModuleBase + NtHeader->OptionalHeader.DataDirectory[DirectoryIndex].VirtualAddress);

	} while (FALSE);

	return RetDirectory;
}

// 根据模块基址和函数名字获取函数地址
ULONG_PTR GetProAddress_FromModule(ULONG_PTR ModuleBase,CHAR* ProcName)
{
	ULONG_PTR ProcAddress = 0;

	IMAGE_EXPORT_DIRECTORY *ExportDirectory = NULL;

	USHORT Index = 0;
	USHORT *ExportOrdinalsArry = NULL;
	ULONG* ExportNameArry = NULL;
	ULONG *ExportAddressArry = NULL;

	do
	{
		ExportDirectory = (IMAGE_EXPORT_DIRECTORY *)GetDirectory(ModuleBase, IMAGE_DIRECTORY_ENTRY_EXPORT);
		if (ExportDirectory == NULL)
		{
			KdPrint(("获取导出表失败！\n"));
			break;
		}

		ExportOrdinalsArry = (USHORT *)(ModuleBase + ExportDirectory->AddressOfNameOrdinals);
		ExportNameArry = (ULONG *)(ModuleBase + ExportDirectory->AddressOfNames);
		ExportAddressArry = (ULONG *)(ModuleBase + ExportDirectory->AddressOfFunctions);

		for (Index = 0; Index < ExportDirectory->NumberOfFunctions; ++Index)
		{
			if (strcmp(ProcName, (CHAR *)(ModuleBase + ExportNameArry[Index])) == 0)
			{
				ProcAddress = ModuleBase + ExportAddressArry[ExportOrdinalsArry[Index]];
				break;
			}
		}

	} while (FALSE);

	return ProcAddress;
}

// 第一个参数是进程PID，第二个参数是进程模块，第三个参数是模块导出函数名
ULONG_PTR GeProcAddressFromProcess(HANDLE ProcessId,WCHAR *ModuleName,CHAR *ProcName)
{
	PEPROCESS AttachedProcess = NULL;
	KAPC_STATE ApcState = { 0 };

	HANDLE ProcessHandle = NULL;

	ZWQUERYINFORMATIONPROCESS ZwQueryInformationProcess = NULL;
	PROCESS_BASIC_INFORMATION BasicInformation = { 0 };
	PPEB Peb = NULL;
	ULONG RetLength = 0;

	PLDR_DATA_TABLE_ENTRY TempLdrEntry = NULL; 
	PLIST_ENTRY InMemoryOrderLinks = NULL;
	UNICODE_STRING uModuleName = { 0 };
	WCHAR *NameBuffer = NULL;
	ULONG Index = 0;

	ULONG_PTR ProcAddress = 0;
	
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	do
	{
		// +3是为了前后各自加一个*
		NameBuffer = sfAllocateMemory(sizeof(WCHAR) * (wcslen(ModuleName) + 3));
		if (NameBuffer == NULL)
		{
			KdPrint(("分配内存失败！\n"));
			break;
		}

		RtlZeroMemory(NameBuffer, sizeof(WCHAR) * (wcslen(ModuleName) + 3));
		NameBuffer[0] = L'*';
		wcscat(NameBuffer, ModuleName);
		for (Index = 1; Index < wcslen(ModuleName); ++Index)
		{
			if (NameBuffer[Index] >= L'a' && NameBuffer[Index] <= L'z')
				NameBuffer[Index] -= (L'a' - L'A');
		}
		wcscat(NameBuffer, L"*");
		RtlInitUnicodeString(&uModuleName, NameBuffer);

		ProcessHandle = OpenProcess(ProcessId);
		if (ProcessHandle == NULL)
		{
			KdPrint(("打开进程失败！\n"));
			break;
		}

		ZwQueryInformationProcess = (ZWQUERYINFORMATIONPROCESS)GetProcAddress(L"ZwQueryInformationProcess");
		if (ZwQueryInformationProcess == NULL)
		{
			KdPrint(("获取ZwQueryInformationProcess失败！\n"));
			break;
		}

		Status = ZwQueryInformationProcess(ProcessHandle, ProcessBasicInformation, &BasicInformation, sizeof(BasicInformation), &RetLength);
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("调用ZwQueryInformationProcess失败！错误码是：%x！\n", Status));
			break;
		}

		Status = PsLookupProcessByProcessId((HANDLE)BasicInformation.UniqueProcessId, &AttachedProcess);
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("调用PsLookupProcessByProcessId失败！错误码是：%x！\n", Status));
			break;
		}

		KeStackAttachProcess(AttachedProcess, &ApcState);

		Peb = (PPEB)BasicInformation.PebBaseAddress;
		if (Peb == NULL || MmIsAddressValid(Peb) == FALSE)
		{
			KdPrint(("Peb地址为不可读！\n"));
			break;
		}

		if (Peb->Ldr == NULL || MmIsAddressValid(Peb->Ldr) == FALSE)
		{
			KdPrint(("Peb->Ldr地址不可读！\n"));
			break;
		}

		if (IsListEmpty(&Peb->Ldr->InMemoryOrderModuleList))
		{
			KdPrint(("Ldr->InMemoryOrderModuleList为空！\n"));
			break;
		}

		InMemoryOrderLinks = Peb->Ldr->InMemoryOrderModuleList.Flink;
		while (InMemoryOrderLinks != &Peb->Ldr->InMemoryOrderModuleList)
		{
			TempLdrEntry = CONTAINING_RECORD(InMemoryOrderLinks, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
			if (FsRtlIsNameInExpression(&uModuleName, &TempLdrEntry->FullDllName, TRUE, NULL) == TRUE)
			{
				ProcAddress = GetProAddress_FromModule((ULONG_PTR)TempLdrEntry->DllBase, ProcName);
				break;
			}

			InMemoryOrderLinks = InMemoryOrderLinks->Flink;
		}

		KeUnstackDetachProcess(&ApcState);

	} while (FALSE);

	sfFreeMemory(NameBuffer);
	sfCloseHandle(ProcessHandle);
	if (AttachedProcess)ObDereferenceObject(AttachedProcess);

	return ProcAddress;
}

CHAR DllPath[] = "C:\\XXX_64.dll";

VOID Test()
{
	ULONG_PTR LoadLibraryA = 0;

	KEINITIALIZEAPC KeInitializeApc = NULL;
	KEINSERTQUEUEAPC KeInsertQueueApc = NULL;

	PKAPC Apc = NULL;
	HANDLE InjectProcessHandle = NULL;
	PKTHREAD InjectThread = NULL;

	PVOID PathBuffer = NULL;
	PVOID ShellCode = NULL;
	ULONG_PTR PathBufferSize = 0;
	ULONG_PTR ShellCodeSize = 0;

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	do
	{
		KeInitializeApc = GetProcAddress(L"KeInitializeApc");
		if (KeInitializeApc == NULL)
		{
			KdPrint(("获取KeInitializeApc函数失败！\n"));
			break;
		}

		KeInsertQueueApc = GetProcAddress(L"KeInsertQueueApc");
		if (KeInsertQueueApc == NULL)
		{
			KdPrint(("获取KeInsertQueueApc函数失败！\n"));
			break;
		}

		LoadLibraryA = GeProcAddressFromProcess((HANDLE)1252, L"Kernel32", "LoadLibraryA");
		if (LoadLibraryA == 0)
			LoadLibraryA = GeProcAddressFromProcess((HANDLE)1252, L"KernelBase", "LoadLibraryA");

		if (LoadLibraryA == 0)
		{
			KdPrint(("LoadLibraryA地址没找到！\n"));
			break;
		}

		InjectThread = FindInjectThread((HANDLE)1252);
		if (InjectThread == NULL)
		{
			KdPrint(("没找到可以Inject的线程！\n"));
			break;
		}

		Apc = sfAllocateMemory(sizeof(KAPC));
		if (Apc == NULL)
		{
			KdPrint(("分配Apc对象失败！\n"));
			break;
		}

		InjectProcessHandle = OpenProcess(PsGetProcessId);
		if (InjectProcessHandle == NULL)
		{
			KdPrint(("OpenProcess失败！\n"));
			break;
		}

		PathBufferSize = sizeof(DllPath);
		Status = ZwAllocateVirtualMemory(InjectProcessHandle, &PathBuffer, 0, (SIZE_T *)&PathBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("分配内存失败！错误码：%x\n", Status));
			return;
		}

		ShellCodeSize = sizeof(NormalRoutine);
		Status = ZwAllocateVirtualMemory(InjectProcessHandle, &ShellCode, 0, (SIZE_T *)&ShellCodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("分配内存失败！错误码：%x\n", Status));
			return;
		}


		//KeInitializeApc(Apc, InjectThread, OriginalApcEnvironment, KernelRoutine, NULL, , UserMode, NULL);

	} while (FALSE);

	
}

VOID Unload(PDRIVER_OBJECT DriverObject)
{
	KdPrint(("Unload Success!\n"));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegString)
{
	KdPrint(("Entry Driver!\n"));
	Test();
	DriverObject->DriverUnload = Unload;
	return STATUS_SUCCESS;
}