#include "main.h"
#include "options.h"

#pragma region CallBacks
OB_PREOP_CALLBACK_STATUS ProcessObjectPreCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);
	VirtualizerStart();
	VirtualizerStrEncryptStart();
#if (PROTECT_PROCESS == 1)
	if (OperationInformation && MmIsAddressValid(OperationInformation))
	{
		HANDLE pid = PsGetProcessId((PEPROCESS)OperationInformation->Object);
		if (pid && pid == (HANDLE)ProcessIdToProtect)
		{
			if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE ||
				OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
			{
				if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_TERMINATE) == PROCESS_TERMINATE)
				{
					OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
				}
				if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_OPERATION) == PROCESS_VM_OPERATION)
				{
					OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
				}
				if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_READ) == PROCESS_VM_READ)
				{
					OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
				}
				if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)
				{
					OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
				}
			}
		}
	}
#endif
	VirtualizerStrEncryptEnd();
	VirtualizerEnd();
	if (PsGetCurrentProcessId() == 4)
	{
		POB_PRE_OPERATION_CALLBACK EACCallBack = (POB_PRE_OPERATION_CALLBACK)ProcessPreOperation;
		EACCallBack(RegistrationContext, OperationInformation);
	}
	if (PsGetCurrentProcessId() == pGameId)
	{
		POB_PRE_OPERATION_CALLBACK EACCallBack = (POB_PRE_OPERATION_CALLBACK)ProcessPreOperation;
		EACCallBack(RegistrationContext, OperationInformation);
	}
	return(OB_PREOP_SUCCESS);
}

VOID ProcessObjectPostCallback(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION OperationInformation)
{
	if (PsGetCurrentProcessId() == 4)
	{
		POB_POST_OPERATION_CALLBACK EACCallBack = (POB_POST_OPERATION_CALLBACK)ProcessPostOperation;
		EACCallBack(RegistrationContext, OperationInformation);
	}
	if (PsGetCurrentProcessId() == pGameId)
	{
		POB_POST_OPERATION_CALLBACK EACCallBack = (POB_POST_OPERATION_CALLBACK)ProcessPostOperation;
		EACCallBack(RegistrationContext, OperationInformation);
	}
	return;
}

OB_PREOP_CALLBACK_STATUS ThreadObjectPreCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	if (PsGetCurrentProcessId() == 4)
	{
		POB_PRE_OPERATION_CALLBACK EACCallBack = (POB_PRE_OPERATION_CALLBACK)ThreadPreOperation;
		EACCallBack(RegistrationContext, OperationInformation);
	}

	return(OB_PREOP_SUCCESS);
}

VOID ThreadObjectPostCallback(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION OperationInformation)
{
	if (PsGetCurrentProcessId() == 4)
	{
		POB_POST_OPERATION_CALLBACK EACCallBack = (POB_POST_OPERATION_CALLBACK)ThreadPostOperation;
		EACCallBack(RegistrationContext, OperationInformation);
	}
	return;
}

BOOLEAN ImageCallBack()
{
#if (REMOVE_IMAGEROUTINE == 1)
	__try
	{
		VirtualizerStart();
		VirtualizerStrEncryptStart();
		ULONG64	NotifyAddr = 0, MagicPtr = 0;
		ULONG64	PspLoadImageNotifyRoutine = (ULONG64)ImageCallBacks;
		for (int i = 0; i < 64; i++)
		{
			MagicPtr = PspLoadImageNotifyRoutine + i * 8;
			NotifyAddr = *(PULONG64)(MagicPtr);
			if (MmIsAddressValid((PVOID)NotifyAddr) && NotifyAddr != 0)
			{
				NotifyAddr = *(PULONG64)(NotifyAddr & 0xfffffffffffffff8);
				if (IsFromEACRange((PVOID)NotifyAddr))
				{
					DbgPrint("[CVEAC-2020-0002] EAC found in ImageCallBacks");
					EAC_ImageRoutine = (PVOID)NotifyAddr;
					if (!NT_SUCCESS(PsRemoveLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)NotifyAddr)))
						DbgPrint("[CVEAC-2020-0002] PsRemoveLoadImageNotifyRoutine failed");
					else
					{
						DbgPrint("[CVEAC-2020-0002] ImageCallBack has been removed");
						return TRUE;
					}
				}
			}
		}
		VirtualizerStrEncryptEnd();
		VirtualizerEnd();
	}
	except(EXCEPTION_EXECUTE_HANDLER)
	{
		VirtualizerStrEncryptStart();
		DbgPrint("[CVEAC-2020-0002] Exception [0x%X] in FuckImageCallBack", GetExceptionCode());
		VirtualizerStrEncryptEnd();
		return FALSE;
	}
#endif
	return FALSE;
}

BOOLEAN ThreadCallBack()
{
#if (REMOVE_THREADROUTINE == 1)
	__try
	{
		VirtualizerStart();
		VirtualizerStrEncryptStart();
		ULONG64	NotifyAddr = 0, MagicPtr = 0;
		ULONG64	PspCreateThreadNotifyRoutine = (ULONG64)ThreadCallBacks;
		for (int i = 0; i < 64; i++)
		{
			MagicPtr = PspCreateThreadNotifyRoutine + i * 8;
			NotifyAddr = *(PULONG64)(MagicPtr);
			if (MmIsAddressValid((PVOID)NotifyAddr) && NotifyAddr != 0)
			{
				NotifyAddr = *(PULONG64)(NotifyAddr & 0xfffffffffffffff8);
				if (IsFromEACRange((PVOID)NotifyAddr))
				{
					DbgPrint("[CVEAC-2020-0002] EAC found in ThreadCallBacks");
					EAC_ThreadRoutine = (PVOID)NotifyAddr;
					if (!NT_SUCCESS(PsRemoveCreateThreadNotifyRoutine((PCREATE_THREAD_NOTIFY_ROUTINE)NotifyAddr)))
						DbgPrint("[CVEAC-2020-0002] PsRemoveCreateThreadNotifyRoutine failed");
					else
					{
						DbgPrint("[CVEAC-2020-0002] ThreadCallBack has been removed");
						return TRUE;
					}
				}
			}
		}
		VirtualizerStrEncryptEnd();
		VirtualizerEnd();
	}
	except(EXCEPTION_EXECUTE_HANDLER)
	{
		VirtualizerStrEncryptStart();
		DbgPrint("[CVEAC-2020-0002] Exception [0x%X] in FuckThreadCallBack", GetExceptionCode());
		VirtualizerStrEncryptEnd();
		return FALSE;
	}
#endif

	return FALSE;
}

BOOLEAN RestoreImageCallBack()
{
	VirtualizerStart();
	VirtualizerStrEncryptStart();
#if (REMOVE_IMAGEROUTINE == 1)
	if (!MmIsAddressValid((PVOID)EAC_ImageRoutine) ||
		!NT_SUCCESS(PsSetLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)EAC_ImageRoutine)))
		DbgPrint("[CVEAC-2020-0002] WARNING : PsSetLoadImageNotifyRoutine failed");
	else
	{
		DbgPrint("[CVEAC-2020-0002] ImageCallBack has been restored");
		return TRUE;
	}
#endif
	VirtualizerStrEncryptEnd();
	VirtualizerEnd();
	return FALSE;
}

BOOLEAN RestoreThreadCallBack()
{
	VirtualizerStart();
	VirtualizerStrEncryptStart();
#if (REMOVE_THREADROUTINE == 1)
	if (!MmIsAddressValid((PVOID)EAC_ThreadRoutine) ||
		!NT_SUCCESS(PsSetCreateThreadNotifyRoutine((PCREATE_THREAD_NOTIFY_ROUTINE)EAC_ThreadRoutine)))
		DbgPrint("[CVEAC-2020-0002] WARNING : PsSetCreateThreadNotifyRoutine failed");
	else
	{
		DbgPrint("[CVEAC-2020-0002] ThreadCallBack has been restored");
		return TRUE;
	}
#endif
	VirtualizerStrEncryptEnd();
	VirtualizerEnd();
	return FALSE;
}

#pragma endregion CallBacks