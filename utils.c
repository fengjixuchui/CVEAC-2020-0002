#include "main.h"
#include "options.h"

#pragma region Utils

NTSTATUS SearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound)
{
	ASSERT(ppFound != NULL && pattern != NULL && base != NULL);
	if (ppFound == NULL || pattern == NULL || base == NULL)
		return STATUS_INVALID_PARAMETER;

	for (ULONG_PTR i = 0; i < size - len; i++)
	{
		BOOLEAN found = TRUE;
		for (ULONG_PTR j = 0; j < len; j++)
		{
			if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j])
			{
				found = FALSE;
				break;
			}
		}
		if (found != FALSE)
		{
			*ppFound = (PUCHAR)base + i;
			return STATUS_SUCCESS;
		}
	}
	return STATUS_NOT_FOUND;
}

PVOID GetKernelBase()
{
	VirtualizerStart();
	VirtualizerStrEncryptStart();
	NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
	PVOID Base = 0;
	ULONG cb = 0x10000;
	do
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		PRTL_PROCESS_MODULES prpm = (PRTL_PROCESS_MODULES)ExAllocatePool(PagedPool, cb);
		if (prpm)
		{
			if (0 <= (status == ZwQuerySystemInformation(0x0B, prpm, cb, &cb)))
			{
				ULONG NumberOfModules = prpm->NumberOfModules;
				if (NumberOfModules)
				{
					PRTL_PROCESS_MODULE_INFORMATION Modules = prpm->Modules;
					do
					{
						if ((ULONG64)Modules->ImageBase > (ULONG64)(0x8000000000000000))
						{
							Base = Modules->ImageBase;
							break;
						}
					} while (Modules++, --NumberOfModules);
				}
			}
			ExFreePool(prpm);
		}

	} while (status == STATUS_INFO_LENGTH_MISMATCH);
	VirtualizerStrEncryptEnd();
	VirtualizerEnd();
	return Base;
}

BOOLEAN IsFromEACRange(PVOID Address)
{
	if ((ULONG64)Address > (ULONG64)EAC_Base &&
		(ULONG64)((ULONG64)EAC_Base + (ULONG64)EAC_Base_Size) > (ULONG64)Address)
	{
		return 1;
	}
	return 0;
}

BOOLEAN SuspendOrResumeAllThreads(BOOLEAN Suspend)
{
	VirtualizerStart();
	VirtualizerStrEncryptStart();
	ULONG cb = 0x20000;
	PSYSTEM_PROCESS_INFORMATION psi = 0;
	PVOID buf = 0;
	NTSTATUS status = 0, rc = 0;
	PETHREAD peThread = 0;
	do
	{
		status = STATUS_INSUFFICIENT_RESOURCES;

		if (buf = ExAllocatePool(PagedPool, cb))
		{
			if (0 <= (status = ZwQuerySystemInformation(5, buf, cb, &cb)))
			{
				psi = (PSYSTEM_PROCESS_INFORMATION)buf;
				while (psi->NextEntryOffset)
				{
					if (psi->UniqueProcessId == (HANDLE)4)
					{
						for (ULONG i = 0; i < psi->NumberOfThreads; i++)
						{
							if (MmIsAddressValid(psi->Threads[i].StartAddress) && IsFromEACRange(psi->Threads[i].StartAddress))
							{
								rc = PsLookupThreadByThreadId(psi->Threads[i].ClientId.UniqueThread, &peThread);
								if (!NT_SUCCESS(rc))
								{
									DbgPrint("[CVEAC-2020-0002] PsLookupThreadByThreadId failed in SuspendOrResumeAllThreads");
									if (buf)
										ExFreePool(buf);
									return 0;
								}
								if (NT_SUCCESS(rc))
								{
									DbgPrint("[CVEAC-2020-0002] Found EAC Thread %d !", psi->Threads[i].ClientId.UniqueThread);
									if (peThread)
									{
										if (Suspend == TRUE)
										{
											if (!NT_SUCCESS(o_PsSuspendThread(peThread, 0)))
												DbgPrint("[CVEAC-2020-0002] o_PsSuspendThread failed.");
										}
										else
											if (!NT_SUCCESS(o_PsResumeThread(peThread)))
												DbgPrint("[CVEAC-2020-0002] o_PsSuspendThread failed.");
									}
								}
							}
						}

					}
					psi = (PSYSTEM_PROCESS_INFORMATION)((ULONG64)(psi)+psi->NextEntryOffset);
				}

			}
			if (buf)
				ExFreePool(buf);
		}

	} while (status == STATUS_INFO_LENGTH_MISMATCH);
	VirtualizerStrEncryptEnd();
	VirtualizerEnd();
	return (status == 0) ? 1 : 0;
}

uintptr_t dereference(uintptr_t address, unsigned int offset)
{
	if (address == 0)
		return 0;

	return address + (int)((*(int*)(address + offset) + offset) + sizeof(int));
}

#pragma endregion Utils
