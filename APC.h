#ifndef _APC_H_
#define _APC_H_

typedef enum _KAPC_ENVIRONMENT {
	OriginalApcEnvironment,											//ԭʼ�Ľ��̻���
	AttachedApcEnvironment,											//�ҿ���Ľ��̻���
	CurrentApcEnvironment,											//��ǰ����
	InsertApcEnvironment											//������ʱ�Ļ���
} KAPC_ENVIRONMENT;													//����APCʱ��Ļ�����ö��ֵ

//����APC�ĺ���
typedef BOOLEAN(*KEINSERTQUEUEAPC)(IN PRKAPC Apc, IN PVOID SystemArgument1, IN PVOID SystemArgument2, IN KPRIORITY Increment);
//��ʼ��APC�ĺ���
typedef VOID(*KEINITIALIZEAPC)(IN PRKAPC Apc, IN PRKTHREAD Thread, IN KAPC_ENVIRONMENT Environment, IN PKKERNEL_ROUTINE KernelRoutine, PKRUNDOWN_ROUTINE RundownRoutine OPTIONAL, IN PKNORMAL_ROUTINE NormalRoutine OPTIONAL, IN KPROCESSOR_MODE ApcMode OPTIONAL, IN PVOID NormalContext OPTIONAL);																	//��ʼ��һ��APC����
//--------------------------APC--------------------------

// �����߳��Ƿ���Ա�����UserApc
BOOLEAN TestInjectApc(PKTHREAD Kthread)
{
	//�����Ǿ���ƫ��
	ULONG ApcQueueable_Offset = 0;
	ULONG Alertable_Offset = 0;

	//������λ
	ULONG ApcQueueable_Bit = 0;
	ULONG Alertable_Bit = 0;

	RTL_OSVERSIONINFOEXW OsVersion = { 0 };

	BOOLEAN RetValue = FALSE;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	do
	{
		OsVersion.dwOSVersionInfoSize = sizeof(OsVersion);
		Status = RtlGetVersion(&OsVersion);
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("��ȡϵͳ�汾ʧ�ܣ�\n"));
			break;
		}

		if (OsVersion.wProductType != VER_NT_WORKSTATION)
		{
			KdPrint(("��֧�ַ���������ϵͳ��\n"));
			break;
		}

		if (sizeof(PVOID) == 8)																	//�����64λϵͳ
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

				Alertable_Offset = 0x4c;
				Alertable_Bit = 1 << 5;
			}
			else
				break;

		}
		else if (sizeof(PVOID) == 4)															// �����32λϵͳ
		{
			break;
		}
		else																					// ��Ͳ�֪��ʲô��ϵͳ��
			break;

		if (*((UCHAR*)Kthread + ApcQueueable_Offset) & ApcQueueable_Bit == 0)
		{
			KdPrint(("�̶߳���%p��ApcQueueableΪ0�������Բ��룡\n", (ULONG_PTR)Kthread));
			break;
		}

		if (*((UCHAR*)Kthread + Alertable_Offset) & Alertable_Bit == 0)
		{
			KdPrint(("�̶߳���%p��AlertableΪ0�������Բ��룡\n", (ULONG_PTR)Kthread));
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
			KdPrint(("��ȡZwQuerySystemInformationʧ�ܣ�\n"));
			break;
		}

		Status = ZwQuerySystemInformation(SystemProcessInformation, ProcessInformation, RetLength, &RetLength);
		if (Status != STATUS_INFO_LENGTH_MISMATCH)
		{
			KdPrint(("��ȡ������Ϣʧ�ܣ��������ǣ�%x\n", Status));
			break;
		}

		ProcessInformation = sfAllocateMemory(RetLength);
		if (ProcessInformation == NULL)
		{
			KdPrint(("�����ڴ�ʧ�ܣ�\n"));
			break;
		}

		Status = ZwQuerySystemInformation(SystemProcessInformation, ProcessInformation, RetLength, &RetLength);
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("��ȡ������Ϣʧ�ܣ��������ǣ�%x\n", Status));
			break;
		}

		while (TRUE)
		{
			if (ProcessId == ProcessInformation->UniqueProcessId)
			{
				for (Index = 0; Index < ProcessInformation->NumberOfThreads; ++Index)
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

	sfFreeMemory(ProcessInformation);

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
UCHAR NormalRoutine[] = "";
#else
UCHAR NormalRoutine[] = "";
#endif


#endif 