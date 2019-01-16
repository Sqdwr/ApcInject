#include "DefineStruct.h"
#include "APC.h"

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
			KdPrint(("����ZwOpenProcessʧ�ܣ��������ǣ�%x��\n", Status));
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
			KdPrint(("��ַΪ�գ�\n"));
			break;
		}

		if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			KdPrint(("DosHeader->e_magic����ȷ��\n"));
			break;
		}

		NtHeader = (IMAGE_NT_HEADERS *)(ModuleBase + DosHeader->e_lfanew);
		if (NtHeader->Signature != IMAGE_NT_SIGNATURE)
		{
			KdPrint(("NtHeader->Signature����ȷ��\n"));
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
			KdPrint(("�ļ�����PE�ļ���\n"));
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
			KdPrint(("��ȡNtHeaderʧ�ܣ�\n"));
			break;
		}

		if (NtHeader->OptionalHeader.DataDirectory[DirectoryIndex].Size == 0)
		{
			KdPrint(("��Ҫ��ȡ��DataDirectory��СΪ�գ�\n"));
			break;
		}

		RetDirectory = (PVOID)(ModuleBase + NtHeader->OptionalHeader.DataDirectory[DirectoryIndex].VirtualAddress);

	} while (FALSE);

	return RetDirectory;
}

// ����ģ���ַ�ͺ������ֻ�ȡ������ַ
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
			KdPrint(("��ȡ������ʧ�ܣ�\n"));
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

// ��һ�������ǽ���PID���ڶ��������ǽ���ģ�飬������������ģ�鵼��������
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
		// +3��Ϊ��ǰ����Լ�һ��*
		NameBuffer = sfAllocateMemory(sizeof(WCHAR) * (wcslen(ModuleName) + 3));
		if (NameBuffer == NULL)
		{
			KdPrint(("�����ڴ�ʧ�ܣ�\n"));
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
			KdPrint(("�򿪽���ʧ�ܣ�\n"));
			break;
		}

		ZwQueryInformationProcess = (ZWQUERYINFORMATIONPROCESS)GetProcAddress(L"ZwQueryInformationProcess");
		if (ZwQueryInformationProcess == NULL)
		{
			KdPrint(("��ȡZwQueryInformationProcessʧ�ܣ�\n"));
			break;
		}

		Status = ZwQueryInformationProcess(ProcessHandle, ProcessBasicInformation, &BasicInformation, sizeof(BasicInformation), &RetLength);
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("����ZwQueryInformationProcessʧ�ܣ��������ǣ�%x��\n", Status));
			break;
		}

		Status = PsLookupProcessByProcessId((HANDLE)BasicInformation.UniqueProcessId, &AttachedProcess);
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("����PsLookupProcessByProcessIdʧ�ܣ��������ǣ�%x��\n", Status));
			break;
		}

		KeStackAttachProcess(AttachedProcess, &ApcState);

		Peb = (PPEB)BasicInformation.PebBaseAddress;
		if (Peb == NULL || MmIsAddressValid(Peb) == FALSE)
		{
			KdPrint(("Peb��ַΪ���ɶ���\n"));
			break;
		}

		if (Peb->Ldr == NULL || MmIsAddressValid(Peb->Ldr) == FALSE)
		{
			KdPrint(("Peb->Ldr��ַ���ɶ���\n"));
			break;
		}

		if (IsListEmpty(&Peb->Ldr->InMemoryOrderModuleList))
		{
			KdPrint(("Ldr->InMemoryOrderModuleListΪ�գ�\n"));
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

CHAR DllPath[] = "C:\\Win32Project1.dll";

VOID Test()
{
	ULONG_PTR LoadLibraryA = 0;

	KEINITIALIZEAPC KeInitializeApc = NULL;
	KEINSERTQUEUEAPC KeInsertQueueApc = NULL;

	HANDLE ProcessId = (HANDLE)1864;

	PKAPC Apc = NULL;
	HANDLE ProcessHandle = NULL;
	PKTHREAD InjectThread = NULL;
	PKPROCESS InjectProcess = NULL;
	KAPC_STATE ApcState = { 0 };

	PVOID PathBuffer = NULL;
	PVOID ShellCode = NULL;
	ULONG_PTR PathBufferSize = 0;
	ULONG_PTR ShellCodeSize = 0;

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	do
	{
		__debugbreak();

		KeInitializeApc = GetProcAddress(L"KeInitializeApc");
		if (KeInitializeApc == NULL)
		{
			KdPrint(("��ȡKeInitializeApc����ʧ�ܣ�\n"));
			break;
		}

		KeInsertQueueApc = GetProcAddress(L"KeInsertQueueApc");
		if (KeInsertQueueApc == NULL)
		{
			KdPrint(("��ȡKeInsertQueueApc����ʧ�ܣ�\n"));
			break;
		}

		LoadLibraryA = GeProcAddressFromProcess(ProcessId, L"Kernel32", "LoadLibraryA");
		if (LoadLibraryA == 0)
			LoadLibraryA = GeProcAddressFromProcess(ProcessId, L"KernelBase", "LoadLibraryA");

		if (LoadLibraryA == 0)
		{
			KdPrint(("LoadLibraryA��ַû�ҵ���\n"));
			break;
		}

		InjectThread = FindInjectThread(ProcessId);
		if (InjectThread == NULL)
		{
			KdPrint(("û�ҵ�����Inject���̣߳�\n"));
			break;
		}

		Apc = sfAllocateMemory(sizeof(KAPC));
		if (Apc == NULL)
		{
			KdPrint(("����Apc����ʧ�ܣ�\n"));
			break;
		}
		RtlZeroMemory(Apc, sizeof(KAPC));

		ProcessHandle = OpenProcess(ProcessId);
		if (ProcessHandle == NULL)
		{
			KdPrint(("OpenProcessʧ�ܣ�\n"));
			break;
		}

		PathBufferSize = sizeof(DllPath);
		Status = ZwAllocateVirtualMemory(ProcessHandle, &PathBuffer, 0, (SIZE_T *)&PathBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("�����ڴ�ʧ�ܣ������룺%x\n", Status));
			return;
		}

		ShellCodeSize = sizeof(NormalRoutine);
		Status = ZwAllocateVirtualMemory(ProcessHandle, &ShellCode, 0, (SIZE_T *)&ShellCodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("�����ڴ�ʧ�ܣ������룺%x\n", Status));
			return;
		}

		Status = PsLookupProcessByProcessId(ProcessId, &InjectProcess);
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("PsLookupProcessByProcessIdʧ�ܣ������룺%x��\n", Status));
			break;
		}

		KeStackAttachProcess(InjectProcess, &ApcState);

		RtlZeroMemory(PathBuffer, PathBufferSize);
		RtlZeroMemory(ShellCode, ShellCodeSize);

		RtlCopyMemory(PathBuffer, DllPath, sizeof(DllPath));
		RtlCopyMemory(ShellCode, NormalRoutine, sizeof(NormalRoutine));

		//KeInitializeApc(Apc, InjectThread, OriginalApcEnvironment, KernelRoutine, NULL, ShellCode, UserMode, NULL);
		//KeInsertQueueApc(Apc, (PVOID)LoadLibraryA, PathBuffer, IO_NO_INCREMENT);

		KeUnstackDetachProcess(&ApcState);

		KeInitializeApc(Apc, InjectThread, OriginalApcEnvironment, KernelRoutine, NULL, ShellCode, UserMode, PathBuffer);
		KeInsertQueueApc(Apc, (PVOID)LoadLibraryA, NULL, IO_NO_INCREMENT);

	} while (FALSE);

	sfCloseHandle(ProcessHandle);
	if (InjectProcess)ObDereferenceObject(InjectProcess);
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