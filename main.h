#pragma once 

#include "ntos.hpp"
#include "ntstructs.hpp"

typedef struct HIDEPROC_STRUCT
{
	ULONG pId;
}HIDEPROC_STRUCT, * PHIDEPROC_STRUCT;

typedef struct IS_ENABLED_STRUCT
{
	BOOLEAN IsEnabled;
}IS_ENABLED_STRUCT, * PIS_ENABLED_STRUCT;

typedef struct GETPROC_STRUCT
{
	ULONG pId;
}GETPROC_STRUCT, * PGETPROC_STRUCT;

#define ctl_protectprocess    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xad138, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define ctl_isenabled    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xad136, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define ctl_getprocid    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xad139, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

ULONG ProcessIdToProtect = 0;
BOOLEAN IsBypassEnabled = 0;
PDEVICE_OBJECT pDeviceObject = 0;


PVOID* ThreadCallBacks = 0, *ImageCallBacks = 0;

PVOID ProcessPostOperation = 0, ProcessPreOperation = 0, ThreadPostOperation = 0, ThreadPreOperation = 0, FilterAddr = 0;
PVOID EAC_ThreadRoutine = 0, EAC_ImageRoutine = 0;

PVOID EAC_Base = 0;
ULONG64 EAC_Base_Size = 0;

HANDLE pParentId = 0, pGameId = 0;
LONG lOperationsOffset = 0;

typedef NTSTATUS(NTAPI* p_PsSuspendThread)(IN PETHREAD Thread, OUT PULONG PreviousCount OPTIONAL);
p_PsSuspendThread o_PsSuspendThread = 0;

typedef NTSTATUS(NTAPI* p_PsResumeThread)(IN PETHREAD Thread);
p_PsResumeThread o_PsResumeThread = 0;

BOOLEAN RestoreImageCallBack();
BOOLEAN RestoreThreadCallBack();

VOID ImageRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO Info);
VOID ProcessRoutine(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create);

NTSTATUS SearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound);
PVOID GetKernelBase();
BOOLEAN IsFromEACRange(PVOID Address);
BOOLEAN SuspendOrResumeAllThreads(BOOLEAN Suspend);
uintptr_t dereference(uintptr_t address, unsigned int offset);
VOID HideDriver(PDRIVER_OBJECT pDriverObject);