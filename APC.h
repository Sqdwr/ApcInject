#ifndef _APC_H_
#define _APC_H_

typedef enum _KAPC_ENVIRONMENT {
	OriginalApcEnvironment,											//原始的进程环境
	AttachedApcEnvironment,											//挂靠后的进程环境
	CurrentApcEnvironment,											//当前环境
	InsertApcEnvironment											//被插入时的环境
} KAPC_ENVIRONMENT;													//挂入APC时候的环境的枚举值

typedef
VOID
(*PKNORMAL_ROUTINE) (
	IN PVOID NormalContext,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2
	);

typedef
VOID
(*PKKERNEL_ROUTINE) (
	IN struct _KAPC *Apc,
	IN OUT PKNORMAL_ROUTINE *NormalRoutine,
	IN OUT PVOID *NormalContext,
	IN OUT PVOID *SystemArgument1,
	IN OUT PVOID *SystemArgument2
	);

typedef
VOID
(*PKRUNDOWN_ROUTINE) (
	IN struct _KAPC *Apc
	);

//插入APC的函数
typedef BOOLEAN(*KEINSERTQUEUEAPC)(IN PRKAPC Apc, IN PVOID SystemArgument1, IN PVOID SystemArgument2, IN KPRIORITY Increment);
//初始化APC的函数
typedef VOID(*KEINITIALIZEAPC)(IN PRKAPC Apc, IN PRKTHREAD Thread, IN KAPC_ENVIRONMENT Environment, IN PKKERNEL_ROUTINE KernelRoutine, PKRUNDOWN_ROUTINE RundownRoutine OPTIONAL, IN PKNORMAL_ROUTINE NormalRoutine OPTIONAL, IN KPROCESSOR_MODE ApcMode OPTIONAL, IN PVOID NormalContext OPTIONAL);																	//初始化一个APC函数
//--------------------------APC--------------------------

// 测试线程是否可以被插入UserApc
BOOLEAN TestInjectApc(PKTHREAD Kthread)
{
	//这里是具体偏移
	ULONG ApcQueueable_Offset = 0;
	ULONG Alertable_Offset = 0;

	//这里是位
	ULONG ApcQueueable_Bit = 0;
	ULONG Alertable_Bit = 0;

	RTL_OSVERSIONINFOEXW OsVersion = { 0 };

	BOOLEAN RetValue = FALSE;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	do
	{
		OsVersion.dwOSVersionInfoSize = sizeof(OsVersion);
		Status = RtlGetVersion((PRTL_OSVERSIONINFOW)&OsVersion);
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("获取系统版本失败！\n"));
			break;
		}

		//XP系统不使用该字段
		if (OsVersion.wProductType != VER_NT_WORKSTATION && OsVersion.dwMajorVersion != 5)
		{
			KdPrint(("不支持服务器类型系统！\n"));
			break;
		}

		if (sizeof(PVOID) == 8)																	//如果是64位系统
		{
			if (OsVersion.dwMajorVersion == 10)													// 10
			{
				if (OsVersion.dwBuildNumber == 10240)
				{
					ApcQueueable_Offset = 0x74;
					ApcQueueable_Bit = 1 << 14;

					Alertable_Offset = 0x74;
					Alertable_Bit = 1 << 4;
				}
				else if (OsVersion.dwBuildNumber == 10586)
				{
					ApcQueueable_Offset = 0x74;
					ApcQueueable_Bit = 1 << 14;

					Alertable_Offset = 0x74;
					Alertable_Bit = 1 << 4;
				}
				else if (OsVersion.dwBuildNumber == 14393)
				{
					ApcQueueable_Offset = 0x74;
					ApcQueueable_Bit = 1 << 14;

					Alertable_Offset = 0x74;
					Alertable_Bit = 1 << 4;
				}
				else if (OsVersion.dwBuildNumber == 15063)
				{
					ApcQueueable_Offset = 0x74;
					ApcQueueable_Bit = 1 << 14;

					Alertable_Offset = 0x74;
					Alertable_Bit = 1 << 4;
				}
				else if (OsVersion.dwBuildNumber == 16299)
				{
					ApcQueueable_Offset = 0x74;
					ApcQueueable_Bit = 1 << 14;

					Alertable_Offset = 0x74;
					Alertable_Bit = 1 << 4;
				}
				else if (OsVersion.dwBuildNumber == 17134)
				{
					ApcQueueable_Offset = 0x74;
					ApcQueueable_Bit = 1 << 14;

					Alertable_Offset = 0x74;
					Alertable_Bit = 1 << 4;
				}
				else if (OsVersion.dwBuildNumber == 17763)
				{
					ApcQueueable_Offset = 0x74;
					ApcQueueable_Bit = 1 << 14;

					Alertable_Offset = 0x74;
					Alertable_Bit = 1 << 4;
				}

			}
			else if (OsVersion.dwMajorVersion == 6 && OsVersion.dwMinorVersion == 3)			// 8.1
			{
				ApcQueueable_Offset = 0x74;
				ApcQueueable_Bit = 1 << 15;

				Alertable_Offset = 0x74;
				Alertable_Bit = 1 << 5;
			}
			else if (OsVersion.dwMajorVersion == 6 && OsVersion.dwMinorVersion == 2)			// 8
			{
				ApcQueueable_Offset = 0x74;
				ApcQueueable_Bit = 1 << 16;

				Alertable_Offset = 0x74;
				Alertable_Bit = 1 << 5;
			}
			else if (OsVersion.dwMajorVersion == 6 && OsVersion.dwMinorVersion == 1)			// 7
			{
				ApcQueueable_Offset = 0x100;
				ApcQueueable_Bit = 1 << 5;

				Alertable_Offset = 0x4C;
				Alertable_Bit = 1 << 5;
			}
			else
				break;

		}
		else if (sizeof(PVOID) == 4)															// 如果是32位系统
		{
			if (OsVersion.dwMajorVersion == 10)													// 10
			{
				if (OsVersion.dwBuildNumber == 10240)
				{
					ApcQueueable_Offset = 0x58;
					ApcQueueable_Bit = 1 << 14;

					Alertable_Offset = 0x58;
					Alertable_Bit = 1 << 4;
				}
				else if (OsVersion.dwBuildNumber == 10586)
				{
					ApcQueueable_Offset = 0x58;
					ApcQueueable_Bit = 1 << 14;

					Alertable_Offset = 0x58;
					Alertable_Bit = 1 << 4;
				}
				else if (OsVersion.dwBuildNumber == 14393)
				{
					ApcQueueable_Offset = 0x58;
					ApcQueueable_Bit = 1 << 14;

					Alertable_Offset = 0x58;
					Alertable_Bit = 1 << 4;
				}
				else if (OsVersion.dwBuildNumber == 15063)
				{
					ApcQueueable_Offset = 0x58;
					ApcQueueable_Bit = 1 << 14;

					Alertable_Offset = 0x58;
					Alertable_Bit = 1 << 4;
				}
				else if (OsVersion.dwBuildNumber == 16299)
				{
					ApcQueueable_Offset = 0x58;
					ApcQueueable_Bit = 1 << 14;

					Alertable_Offset = 0x58;
					Alertable_Bit = 1 << 4;
				}
				else if (OsVersion.dwBuildNumber == 17134)
				{
					ApcQueueable_Offset = 0x58;
					ApcQueueable_Bit = 1 << 14;

					Alertable_Offset = 0x58;
					Alertable_Bit = 1 << 4;
				}
				else if (OsVersion.dwBuildNumber == 17763)
				{
					ApcQueueable_Offset = 0x58;
					ApcQueueable_Bit = 1 << 14;

					Alertable_Offset = 0x58;
					Alertable_Bit = 1 << 4;
				}

			}
			else if (OsVersion.dwMajorVersion == 6 && OsVersion.dwMinorVersion == 3)			// 8.1
			{
				ApcQueueable_Offset = 0x58;
				ApcQueueable_Bit = 1 << 15;

				Alertable_Offset = 0x58;
				Alertable_Bit = 1 << 5;
			}
			else if (OsVersion.dwMajorVersion == 6 && OsVersion.dwMinorVersion == 2)			// 8
			{
				ApcQueueable_Offset = 0x58;
				ApcQueueable_Bit = 1 << 16;

				Alertable_Offset = 0x58;
				Alertable_Bit = 1 << 5;
			}
			else if (OsVersion.dwMajorVersion == 6 && OsVersion.dwMinorVersion == 1)			// 7
			{
				ApcQueueable_Offset = 0xB8;
				ApcQueueable_Bit = 1 << 5;

				Alertable_Offset = 0x3C;
				Alertable_Bit = 1 << 5;
			}
			else if (OsVersion.dwMajorVersion == 5 && OsVersion.dwMinorVersion == 1)
			{
				ApcQueueable_Offset = 0x166;
				ApcQueueable_Bit = 1;

				Alertable_Offset = 0x164;
				Alertable_Bit = 1;
			}
			else
				break;
		}
		else																					// 这就不知道什么鬼系统了
			break;

		KdPrint(("ApcQueueable:%x!\n", *(ULONG*)((UCHAR*)Kthread + ApcQueueable_Offset)));
		if ((*(ULONG*)((UCHAR*)Kthread + ApcQueueable_Offset) & ApcQueueable_Bit) == 0)
		{
			KdPrint(("线程对象：%p，ApcQueueable为0，不可以插入！\n", (ULONG_PTR)Kthread));
			break;
		}
		
		KdPrint(("Alertable:%x!\n", *(ULONG*)((UCHAR*)Kthread + Alertable_Offset)));
		if ((*(ULONG*)((UCHAR*)Kthread + Alertable_Offset) & Alertable_Bit) == 0)
		{
			KdPrint(("线程对象：%p，Alertable为0，不可以插入！\n", (ULONG_PTR)Kthread));
			break;
		}

		RetValue = TRUE;

	} while (FALSE);

	return RetValue;
}

PKTHREAD FindInjectThread(HANDLE ProcessId)
{
	ZWQUERYSYSTEMINFORMATION ZwQuerySystemInformation = NULL;
	PSYSTEM_PROCESS_INFORMATION ProcessInformation = NULL;

	ULONG Index = 0;
	ULONG RetLength = 0;
	PKTHREAD InjectThread = NULL;

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	do
	{
		ZwQuerySystemInformation = (ZWQUERYSYSTEMINFORMATION)GetProcAddress(L"ZwQuerySystemInformation");
		if (ZwQuerySystemInformation == NULL)
		{
			KdPrint(("获取ZwQuerySystemInformation失败！\n"));
			break;
		}

		Status = ZwQuerySystemInformation(SystemProcessInformation, ProcessInformation, RetLength, &RetLength);
		if (Status != STATUS_INFO_LENGTH_MISMATCH)
		{
			KdPrint(("获取进程信息失败！错误码是：%x\n", Status));
			break;
		}

		ProcessInformation = sfAllocateMemory(RetLength);
		if (ProcessInformation == NULL)
		{
			KdPrint(("分配内存失败！\n"));
			break;
		}

		Status = ZwQuerySystemInformation(SystemProcessInformation, ProcessInformation, RetLength, &RetLength);
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("获取进程信息失败！错误码是：%x\n", Status));
			break;
		}
		
		while (TRUE)
		{
			if (ProcessId == ProcessInformation->UniqueProcessId)
			{
				//就没搞懂为什么注入就崩掉了，成功的线程Kthrea->State是5，崩溃的也是5
				//WaitMode都是UserMode
				//for (Index = 0; Index < ProcessInformation->NumberOfThreads; ++Index)
				for (Index = ProcessInformation->NumberOfThreads - 1; Index > 0; --Index)
				{
					Status = PsLookupThreadByThreadId(ProcessInformation->Threads[Index].ClientId.UniqueThread, &InjectThread);
					if (!NT_SUCCESS(Status))
						continue;

					if (TestInjectApc(InjectThread) == FALSE)
					{
						ObDereferenceObject(InjectThread);
						InjectThread = NULL;
					}
					else
						break;
				}

				if (InjectThread != NULL)
					break;
			}

			if (ProcessInformation->NextEntryOffset == 0)
				break;

			ProcessInformation = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)(ProcessInformation)+ProcessInformation->NextEntryOffset);
		}

	} while (FALSE);

	//sfFreeMemory(ProcessInformation);

	return InjectThread;
}

VOID KernelRoutine(KAPC *Apc,PKNORMAL_ROUTINE *NormalRoutine,PVOID *NormalContext,PVOID *SystemArgument1,PVOID *SystemArgument2)
{
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);
	sfFreeMemory(Apc);
}

#ifdef _WIN64

UCHAR NormalRoutine[] =
"\x48\x83\xEC\x18"													//sub rsp,18h
"\xFF\xD2"															//call rdx
"\x48\x83\xC4\x18"													//add rsp,18h
"\xC3";																//ret

#else
UCHAR NormalRoutine[] = 
"\x55"																//push ebp
"\x89\xE5"															//mov ebp,esp
"\x8B\x5D\x08"														//mov ebx,dword ptr[ebp + 8h]
"\x8B\x45\x0C"														//mov eax,dword ptr[ebp+ Ch]
"\x53"																//push ebx
"\xFF\xD0"															//call eax
"\x89\xEC"															//mov esp,ebp
"\x5D"																//pop ebp
"\xC2\x0C\x00";														//ret Ch
#endif


#endif 