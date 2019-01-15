#ifndef _DEFINE_STRUCT_H_
#define _DEFINE_STRUCT_H_

#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>

#define sfAllocateMemory(SIZE) ExAllocatePoolWithTag(PagedPool,SIZE,'tag')
#define sfFreeMemory(P) if(P){ExFreePoolWithTag(P,'tag');P = NULL;}

#define sfCloseHandle(P) if(P){ZwClose(P);P = NULL;}

typedef struct _PEB_LDR_DATA {
	UCHAR Reserved1[8];
	PVOID Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
	PVOID Reserved3[2];
	UNICODE_STRING FullDllName;
	UCHAR Reserved4[8];
	PVOID Reserved5[3];
	union {
		ULONG CheckSum;
		PVOID Reserved6;
	} DUMMYUNIONNAME;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	UCHAR Reserved1[16];
	PVOID Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef VOID(NTAPI *PPS_POST_PROCESS_INIT_ROUTINE) (VOID);

typedef struct _PEB {
	UCHAR Reserved1[2];
	UCHAR BeingDebugged;
	UCHAR Reserved2[1];
	PVOID Reserved3[2];
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID Reserved4[3];
	PVOID AtlThunkSListPtr;
	PVOID Reserved5;
	ULONG Reserved6;
	PVOID Reserved7;
	ULONG Reserved8;
	ULONG AtlThunkSListPtr32;
	PVOID Reserved9[45];
	UCHAR Reserved10[96];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	UCHAR Reserved11[128];
	PVOID Reserved12[1];
	ULONG SessionId;
} PEB, *PPEB;
//--------------------------PEB--------------------------

typedef NTSTATUS(*ZWQUERYINFORMATIONPROCESS)(IN HANDLE ProcessHandle, IN PROCESSINFOCLASS ProcessInformationClass, OUT PVOID ProcessInformation, IN ULONG ProcessInformationLength, OUT PULONG ReturnLength);
//--------------------------ZwQueryInformationProcess--------------------------

typedef NTSTATUS(*ZWQUERYSYSTEMINFORMATION)(IN ULONG SystemInformationClass, OUT PVOID SystemInformation, IN ULONG SystemInformationLength, OUT PULONG ReturnLength);
//--------------------------ZwQuerySystemInformation--------------------------


#define SystemProcessInformation 5

typedef enum _THREAD_STATE{
	StateInitialized,
	StateReady,
	StateRunning,
	StateStandby,
	StateTerminated,
	StateWait,
	StateTransition,
	StateUnknown
} THREAD_STATE;

typedef struct _SYSTEM_THREAD_INFORMATION
{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	THREAD_STATE ThreadState;
	KWAIT_REASON WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR PageDirectoryBase;

	//
	// This part corresponds to VM_COUNTERS_EX.
	// NOTE: *NOT* THE SAME AS VM_COUNTERS!
	//
	SIZE_T PeakVirtualSize;
	ULONG VirtualSize;
	SIZE_T PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;

	//
	// This part corresponds to IO_COUNTERS
	//
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;

	SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;
//--------------------------SYSTEM_PROCESS_INFORMATION--------------------------

PVOID GetProcAddress(WCHAR *wProcName)
{
	UNICODE_STRING uProcName = { 0 };

	RtlInitUnicodeString(&uProcName, wProcName);

	return MmGetSystemRoutineAddress(&uProcName);
}

#endif