#include "main.h"
#include "Options.h"

BOOLEAN RemoveMiniFilter()
{
#if (REMOVE_FILTER == 1)
	VirtualizerStart();
	VirtualizerStrEncryptStart();
	NTSTATUS status = STATUS_SUCCESS;
	ULONG ulFilterListSize = 0;
	PFLT_FILTER* ppFilterList = NULL;
	ULONG i = 0;
	PFLT_OPERATION_REGISTRATION pFltOperationRegistration = NULL;
	FltEnumerateFilters(NULL, 0, &ulFilterListSize);
	ppFilterList = (PFLT_FILTER*)ExAllocatePool(NonPagedPool, ulFilterListSize * sizeof(PFLT_FILTER));
	if (NULL == ppFilterList)
	{
		DbgPrint("[CVEAC-2020-0002] ExAllocatePool Error!\n");
		return FALSE;
	}
	status = FltEnumerateFilters(ppFilterList, ulFilterListSize, &ulFilterListSize);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[CVEAC-2020-0002] FltEnumerateFilters Error![0x%X]\n", status);
		return FALSE;
	}
	DbgPrint("[CVEAC-2020-0002] ulFilterListSize=%d\n", ulFilterListSize);
	if (lOperationsOffset == 0)
	{
		DbgPrint("[CVEAC-2020-0002] GetOperationsOffset Error\n");
		return FALSE;
	}
	try
	{
		for (i = 0; i < ulFilterListSize; i++)
		{
			pFltOperationRegistration = (PFLT_OPERATION_REGISTRATION)(*(PVOID*)((PUCHAR)ppFilterList[i] + lOperationsOffset));
			try
			{
				while (IRP_MJ_OPERATION_END != pFltOperationRegistration->MajorFunction)
				{
					if (MmIsAddressValid(pFltOperationRegistration->PreOperation) &&
						IsFromEACRange(pFltOperationRegistration->PreOperation))
					{
						FilterAddr = pFltOperationRegistration->PreOperation;
						pFltOperationRegistration->PreOperation = DummyObjectPreCallback;
						DbgPrint("[CVEAC-2020-0002] BE Filter found 0x%llX", FilterAddr);
						break;
					}
					pFltOperationRegistration = (PFLT_OPERATION_REGISTRATION)((PUCHAR)pFltOperationRegistration + sizeof(FLT_OPERATION_REGISTRATION));
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				DbgPrint("[CVEAC-2020-0002] Exception [0x%X] in RemoveMiniFilter", GetExceptionCode());
			}
			FltObjectDereference(ppFilterList[i]);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("[CVEAC-2020-0002] Exception [0x%X] in RemoveMiniFilter", GetExceptionCode());
	}
	VirtualizerStrEncryptEnd();
	VirtualizerEnd();
	ExFreePool(ppFilterList);
	ppFilterList = NULL;
#endif
	return TRUE;
}

BOOLEAN RestoreMiniFilter()
{
#if (REMOVE_FILTER == 1)
	NTSTATUS status = STATUS_SUCCESS;
	ULONG ulFilterListSize = 0;
	PFLT_FILTER* ppFilterList = NULL;
	ULONG i = 0;
	PFLT_OPERATION_REGISTRATION pFltOperationRegistration = NULL;
	try
	{
		VirtualizerStart();
		VirtualizerStrEncryptStart();
		FltEnumerateFilters(NULL, 0, &ulFilterListSize);
		ppFilterList = (PFLT_FILTER*)ExAllocatePool(NonPagedPool, ulFilterListSize * sizeof(PFLT_FILTER));
		if (NULL == ppFilterList)
		{
			DbgPrint("[CVEAC-2020-0002] ExAllocatePool Error!\n");
			return FALSE;
		}
		status = FltEnumerateFilters(ppFilterList, ulFilterListSize, &ulFilterListSize);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("[CVEAC-2020-0002] FltEnumerateFilters Error![0x%X]\n", status);
			return FALSE;
		}
		DbgPrint("[CVEAC-2020-0002] ulFilterListSize=%d\n", ulFilterListSize);
		if (lOperationsOffset == 0)
		{
			DbgPrint("[CVEAC-2020-0002] GetOperationsOffset Error\n");
			return FALSE;
		}
		for (i = 0; i < ulFilterListSize; i++)
		{
			pFltOperationRegistration = (PFLT_OPERATION_REGISTRATION)(*(PVOID*)((PUCHAR)ppFilterList[i] + lOperationsOffset));
			try
			{
				while (IRP_MJ_OPERATION_END != pFltOperationRegistration->MajorFunction)
				{
					if (pFltOperationRegistration->PreOperation == DummyObjectPreCallback)
					{
						pFltOperationRegistration->PreOperation = pFltOperationRegistration->PreOperation;
						DbgPrint("[CVEAC-2020-0002] EAC Filter restored");
					}
					pFltOperationRegistration = (PFLT_OPERATION_REGISTRATION)((PUCHAR)pFltOperationRegistration + sizeof(FLT_OPERATION_REGISTRATION));
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				DbgPrint("[CVEAC-2020-0002] Exception [0x%X] in RemoveMiniFilter", GetExceptionCode());
			}
			FltObjectDereference(ppFilterList[i]);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("[CVEAC-2020-0002] Exception [0x%X] in RemoveMiniFilter", GetExceptionCode());
	}
	VirtualizerStrEncryptEnd();
	VirtualizerEnd();

	ExFreePool(ppFilterList);
	ppFilterList = NULL;
#endif
	return TRUE;
}