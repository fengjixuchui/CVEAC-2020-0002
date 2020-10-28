#include "main.h"
#include "options.h"

const WCHAR dNameBuffer[] = L"\\Device\\CVEAC-2020-0002";
const WCHAR dSymLinkBuffer[] = L"\\DosDevices\\CVEAC-2020-0002";

NTSTATUS DeviceIoHandler(PDEVICE_OBJECT devicDriverObjecte_obj, PIRP IRP);
NTSTATUS DeviceCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DeviceClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);

BOOLEAN Do_Bypass()
{
	PLIST_ENTRY FirstEntry = 0;
	PLIST_ENTRY pEntry = 0;;
	__try
	{
		VirtualizerStart();
		VirtualizerStrEncryptStart();
#if (REMOVE_PROCESSCALLBACKS == 1)
		if (ProcessPostOperation || ProcessPreOperation)
			return TRUE;
#if (SUSPEND_EAC == 1)
		if (!NT_SUCCESS(SuspendOrResumeAllThreads(1)))
		{
			DbgPrint("[CVEAC-2020-0002] SuspendOrResumeAllThreads failed.");
			return FALSE;
		}
#endif
		FirstEntry = (PLIST_ENTRY)((uintptr_t)* PsProcessType + 0xC8);
		pEntry = FirstEntry;
		while (pEntry != NULL || pEntry != FirstEntry)
		{
			CALLBACK_ENTRY_ITEM* curCallback = (CALLBACK_ENTRY_ITEM*)pEntry;
			if (!MmIsAddressValid(pEntry))
				break;
			if (IsFromEACRange((PVOID)curCallback->PostOperation) ||
				IsFromEACRange((PVOID)curCallback->PreOperation))
			{
				ProcessPostOperation = (PVOID)curCallback->PostOperation;
				ProcessPreOperation = (PVOID)curCallback->PreOperation;
				curCallback->PostOperation = (POB_POST_OPERATION_CALLBACK)ProcessObjectPostCallback;
				curCallback->PreOperation = (POB_PRE_OPERATION_CALLBACK)ProcessObjectPreCallback;
				break;
			}
			pEntry = pEntry->Flink;
			if (pEntry == FirstEntry || pEntry == 0 || !MmIsAddressValid(pEntry) || !MmIsAddressValid(pEntry)) break;
		}
#endif
#if (REMOVE_THREADCALLBACKS == 1)
		FirstEntry = (PLIST_ENTRY)((uintptr_t)* PsThreadType + 0xC8);
		pEntry = FirstEntry;
		while (pEntry != NULL || pEntry != FirstEntry)
		{
			CALLBACK_ENTRY_ITEM* curCallback = (CALLBACK_ENTRY_ITEM*)pEntry;
			if (!MmIsAddressValid(pEntry))
				break;
			if (IsFromEACRange((PVOID)curCallback->PostOperation) ||
				IsFromEACRange((PVOID)curCallback->PreOperation))
			{
				ThreadPostOperation = (PVOID)curCallback->PostOperation;
				ThreadPreOperation = (PVOID)curCallback->PreOperation;
				curCallback->PostOperation = (POB_POST_OPERATION_CALLBACK)ThreadObjectPostCallback;
				curCallback->PreOperation = (POB_PRE_OPERATION_CALLBACK)ThreadObjectPreCallback;
				break;
			}
			pEntry = pEntry->Flink;
			if (pEntry == FirstEntry || pEntry == 0 || !MmIsAddressValid(pEntry) || !MmIsAddressValid(pEntry)) break;
		}
#endif
		VirtualizerStrEncryptEnd();
		VirtualizerEnd();
	}
	except(EXCEPTION_EXECUTE_HANDLER)
	{
		VirtualizerStrEncryptStart();
		DbgPrint("[CVEAC-2020-0002] Exception [0x%X] in Do_Bypass", GetExceptionCode());
		VirtualizerStrEncryptEnd();
		return FALSE;
	}
	return TRUE;
}

BOOLEAN Remove_Bypass()
{
	PLIST_ENTRY FirstEntry = 0;
	PLIST_ENTRY pEntry = 0;
	__try
	{
		VirtualizerStart();
		VirtualizerStrEncryptStart();
#if (REMOVE_PROCESSCALLBACKS == 1)
		FirstEntry = (PLIST_ENTRY)((uintptr_t)* PsProcessType + 0xC8);
		pEntry = FirstEntry;
		while (pEntry != NULL || pEntry != FirstEntry)
		{
			CALLBACK_ENTRY_ITEM* curCallback = (CALLBACK_ENTRY_ITEM*)pEntry;
			if (!MmIsAddressValid(pEntry))
				break;
			if (curCallback->PostOperation == ProcessObjectPostCallback ||
				curCallback->PreOperation == ProcessObjectPreCallback)
			{
				curCallback->PostOperation = (POB_POST_OPERATION_CALLBACK)ProcessPostOperation;
				curCallback->PreOperation = (POB_PRE_OPERATION_CALLBACK)ProcessPreOperation;
				ProcessPostOperation = 0;
				ProcessPreOperation = 0;
				break;
			}
			pEntry = pEntry->Flink;
			if (pEntry == FirstEntry || pEntry == 0 || !MmIsAddressValid(pEntry)) break;
		}
#endif
#if (REMOVE_THREADCALLBACKS == 1)
		FirstEntry = (PLIST_ENTRY)((uintptr_t)* PsThreadType + 0xC8);
		pEntry = FirstEntry;
		while (pEntry != NULL || pEntry != FirstEntry)
		{
			CALLBACK_ENTRY_ITEM* curCallback = (CALLBACK_ENTRY_ITEM*)pEntry;
			if (!MmIsAddressValid(pEntry))
				break;
			if (curCallback->PostOperation == ThreadObjectPostCallback ||
				curCallback->PreOperation == ThreadObjectPreCallback)
			{
				curCallback->PostOperation = (POB_POST_OPERATION_CALLBACK)ThreadPostOperation;
				curCallback->PreOperation = (POB_PRE_OPERATION_CALLBACK)ThreadPreOperation;
				ThreadPostOperation = 0;
				ThreadPreOperation = 0;
				break;
			}
			pEntry = pEntry->Flink;
			if (pEntry == FirstEntry || pEntry == 0 || !MmIsAddressValid(pEntry)) break;
		}
#endif
#if (SUSPEND_EAC == 1)
		if (!NT_SUCCESS(SuspendOrResumeAllThreads(0)))
		{
			DbgPrint("[CVEAC-2020-0002] SuspendOrResumeAllThreads failed.");
			return FALSE;
		}
#endif
		VirtualizerStrEncryptEnd();
		VirtualizerEnd();
	}
	except(EXCEPTION_EXECUTE_HANDLER)
	{
		VirtualizerStrEncryptStart();
		DbgPrint("[CVEAC-2020-0002] Exception [0x%X] in Remove_Bypass", GetExceptionCode());
		VirtualizerStrEncryptEnd();
		return FALSE;
	}
	return TRUE;
}





#pragma region Routines
VOID ImageRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO Info)
{
	UNREFERENCED_PARAMETER(ProcessId);
	//VirtualizerStart();
	if (wcsstr(FullImageName->Buffer, L"EasyAntiCheat.sys"))
	{
		EAC_Base = Info->ImageBase;
		EAC_Base_Size = Info->ImageSize;
		VirtualizerStrEncryptStart();
		DbgPrint("[CVEAC-2020-0002] EAC found in ImageRoutine 0x%llX %d", EAC_Base, EAC_Base_Size);
		VirtualizerStrEncryptEnd();
	}
	//VirtualizerEnd();
}

VOID ProcessRoutine(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create)
{
	VirtualizerStart();
	VirtualizerStrEncryptStart();
	LPSTR lpFileName = 0;
	PEPROCESS Process = 0;
	if (ProcessId == pGameId && pGameId)
	{
		if (Create == 0)
		{
			DbgPrint("[CVEAC-2020-0002] Protected process %d close %I64x %I64x", ProcessId, EAC_Base, EAC_Base_Size);
			if (ProcessPreOperation || ProcessPostOperation || ThreadPreOperation || ThreadPostOperation)
			{

				if (Remove_Bypass() == FALSE)
					DbgPrint("[CVEAC-2020-0002] WARNING : Remove_Bypass failed");
			}
			IsBypassEnabled = FALSE;
			if (FilterAddr)
			{
				if (!RestoreMiniFilter())
					DbgPrint("[CVEAC-2020-0002] WARNING : RestoreMiniFilter failed");
			}
#if (RESTORE_ROUTINES == 1)

#endif
		}
	}
	if (ProcessId == pParentId && pParentId)
	{
		if (Create == 0)
		{
			DbgPrint("[CVEAC-2020-0002] Protected launcher %d close %I64x %I64x", ProcessId);
			if (FuckImageCallBack() == FALSE)
				DbgPrint("[CVEAC-2020-0002] WARNING : FuckImageCallBack failed");
			if (FuckThreadCallBack() == FALSE)
				DbgPrint("[CVEAC-2020-0002] WARNING : FuckThreadCallBack failed");
			if (!RemoveMiniFilter())
				DbgPrint("[CVEAC-2020-0002] WARNING : RemoveMiniFilter failed");
		}
	}
	if (!NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process)))
	{
		DbgPrint("[CVEAC-2020-0002] WARNING : PsLookupProcessByProcessId failed");
		return;
	}
	if (MmIsAddressValid(Process))
	{
		lpFileName = (LPSTR)PsGetProcessImageFileName(Process);
		if (MmIsAddressValid(lpFileName))
		{
			if (!_stricmp(lpFileName, "YourEACGame.exe") ||
				strstr(lpFileName, "YourEACGame.exe"))
			{
				if (Create)
				{
					pParentId = ParentId;
					pGameId = ProcessId;
					DbgPrint("[CVEAC-2020-0002] Protected process %d found %I64x %I64x", ProcessId, EAC_Base, EAC_Base_Size);
					FilterAddr = 0;
					IsBypassEnabled = FALSE;
					if (Do_Bypass() == FALSE)
						DbgPrint("[CVEAC-2020-0002] WARNING : Do_Bypass failed");
					IsBypassEnabled = TRUE;
#if (RESTORE_ROUTINES == 1)
					if (RestoreThreadCallBack() == FALSE)
						DbgPrint("[CVEAC-2020-0002] WARNING : RestoreImageCallBack failed.");
					if (RestoreImageCallBack() == FALSE)
						DbgPrint("[CVEAC-2020-0002] WARNING : RestoreImageCallBack failed.");

#endif
				}
			}
		}
	}

	VirtualizerStrEncryptEnd();
	VirtualizerEnd();
}


#pragma endregion Routines

BOOLEAN InitBypass()
{
	VirtualizerStart();
	VirtualizerStrEncryptStart();
	BOOLEAN Result = FALSE;
	RTL_OSVERSIONINFOW	osInfo;
	PVOID Base = 0;
	PIMAGE_NT_HEADERS64 Header = 0;
	PIMAGE_SECTION_HEADER pFirstSec = 0;
	ANSI_STRING s1, s2;
	PVOID pFound = 0;
	NTSTATUS status = -1;
	RtlFillMemory(&osInfo, sizeof(RTL_OSVERSIONINFOW), 0);
	RtlFillMemory(&s1, sizeof(ANSI_STRING), 0);
	RtlFillMemory(&s2, sizeof(ANSI_STRING), 0);
	osInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
	RtlGetVersion(&osInfo);

	DbgPrint("[CVEAC-2020-0002] OsInfo: BuildNumber[%ld] dwMajorVersion[%d] dwMinorVersion[%d]", osInfo.dwBuildNumber, osInfo.dwMajorVersion, osInfo.dwMinorVersion);
	if (6 == osInfo.dwMajorVersion)
	{
		if (osInfo.dwMinorVersion == 1)
		{
			DbgPrint("[CVEAC-2020-0002] Windows 7 detected");
			//Windows 7
			Base = GetKernelBase();
			if (Base == 0)
			{
				DbgPrint("[CVEAC-2020-0002] GetKernelBase failed.");
				return Result;
			}
			Header = RtlImageNtHeader(Base);
			pFirstSec = (PIMAGE_SECTION_HEADER)(Header + 1);
			for (PIMAGE_SECTION_HEADER pSec = pFirstSec; pSec < pFirstSec + (Header->FileHeader.NumberOfSections); pSec++)
			{
				RtlInitAnsiString(&s1, "PAGE");
				RtlInitAnsiString(&s2, (PCCHAR)pSec->Name);
				if (RtlCompareString(&s1, &s2, TRUE) == 0)
				{
					//BE ?? ?? ?? ?? 6A 00 8B CB 8B C6 E8 ?? ?? ?? ??  84 C0 75 20 83 C7 04 83 C6 04 81 ?? ?? ?? ?? ?? 72 E3 53 E8 ?? ?? ?? ??  B8 ?? ?? ?? ??  5F
					UCHAR ImageCallBacks_pattern[] = "\x48\x8D\x0D\xCC\xCC\xCC\xCC\x45\x33\xC0\x48\x8B\xD7\x48\x8D\x0C\xD9\xE8\xCC\xCC\xCC\xCC\x84\xC0\x75\xCC\xFF\xC3\x83\xFB\x08\xCC\xCC\x48\x8B\xCF";
					UCHAR ImageCallBacks_pattern2[] = "\xBE\xCC\xCC\xCC\xCC\x6A\x00\x8B\xCB\x8B\xC6\xE8\xCC\xCC\xCC\xCC\x84\xC0\x75\x20\x83\xC7\x04\x83\xC6\x04\x81\xCC\xCC\xCC\xCC\xCC\x72\xE3\x53\xE8\xCC\xCC\xCC\xCC\xB8\xCC\xCC\xCC\xCC";
					//BE ?? ?? ?? ?? 6A 00 8B CB 8B C6 E8 ?? ?? ?? ??  84 C0 75 20 83 C7 04 83 C6 04 81 ?? ?? ?? ?? ?? 72 E3 53 E8 ?? ?? ?? ??  B8 ?? ?? ?? ??  5E
					UCHAR ThreadCallBacks_pattern[] = "\x48\x8D\x1D\xCC\xCC\xCC\xCC\x41\xBF\x40\x00\x00\x00\x48\x8B\xCB";
					UCHAR ThreadCallBacks_pattern2[] = "\xBE\xCC\xCC\xCC\xCC\x6A\x00\x8B\xCB\x8B\xC\xE8\xCC\xCC\xCC\xCC\x84\xC0\x75\x20\x83\xC7\x04\x83\xC6\x04\x81\xCC\xCC\xCC\xCC\xCC\x72\xE3\x53\xE8\xCC\xCC\xCC\xCC\xB8\xCC\xCC\xCC\xCC\x5E";
					UCHAR PsSuspendThread_pattern[] = "\xE8\xCC\xCC\xCC\xCC\x8B\xF8\x48\x8B\x4C\x24\x68\xE8\xCC\xCC\xCC\xCC\xCC\x48";
					//E8 ?? ?? ?? ?? 53 8B 45 08 E8 ?? ?? ?? ?? 8B D8 85 DB 75 E9
					UCHAR PsSuspendThread_pattern2[] = "\xE8\xCC\xCC\xCC\xCC\x53\x8B\x45\x08\xE8\xCC\xCC\xCC\xCC\x8B\xD8\x85\xDB\x75\xE9";
					// E8 ?? ?? ?? ?? 8B D8 85 DB 75 EA 8B 0F 83 E1 FE
					UCHAR PsResumeThread_pattern[] = "\xE8\xCC\xCC\xCC\xCC\x8B\xF8\x48\x8B\x4C\x24\x60\xE8";
					UCHAR PsResumeThread_pattern2[] = "\xE8\xCC\xCC\xCC\xCC\x8B\xD8\x85\xDB\x75\xEA\x8B\x0F\x83\xE1\xFE";
					status = SearchPattern(ImageCallBacks_pattern, 0xCC, sizeof(ImageCallBacks_pattern) - 1, (void*)((PUCHAR)(Base)+pSec->VirtualAddress), pSec->Misc.VirtualSize, &pFound);
					if (NT_SUCCESS(status))
						ImageCallBacks = (PVOID*)dereference((uintptr_t)pFound, 3);
					if (!ImageCallBacks)
					{
						status = SearchPattern(ImageCallBacks_pattern2, 0xCC, sizeof(ImageCallBacks_pattern2) - 1, (void*)((PUCHAR)(Base)+pSec->VirtualAddress), pSec->Misc.VirtualSize, &pFound);
						if (NT_SUCCESS(status))
						{
							DbgPrint("[CVEAC-2020-0002] ImageCallBacks found!!");
							ImageCallBacks = *(uintptr_t*)((uintptr_t)(pFound)+1);
						}
						if (!ImageCallBacks)
						{
							DbgPrint("[CVEAC-2020-0002] ImageCallBacks not found.");
							return Result;
						}
					}
					
					pFound = 0;
					status = SearchPattern(ThreadCallBacks_pattern, 0xCC, sizeof(ThreadCallBacks_pattern) - 1, (void*)((PUCHAR)(Base)+pSec->VirtualAddress), pSec->Misc.VirtualSize, &pFound);
					if (NT_SUCCESS(status))
						ThreadCallBacks = (PVOID*)dereference((uintptr_t)pFound, 3);
					if (!ThreadCallBacks)
					{
						status = SearchPattern(ThreadCallBacks_pattern2, 0xCC, sizeof(ThreadCallBacks_pattern2) - 1, (void*)((PUCHAR)(Base)+pSec->VirtualAddress), pSec->Misc.VirtualSize, &pFound);
						if (NT_SUCCESS(status))
							ThreadCallBacks = *(uintptr_t*)((uintptr_t)(pFound)+1);
						if (!ThreadCallBacks)
						{
							DbgPrint("[CVEAC-2020-0002] ThreadCallBacks not found.");
							return Result;
						}
					}
					
					pFound = 0;
					status = SearchPattern(PsSuspendThread_pattern, 0xCC, sizeof(PsSuspendThread_pattern) - 1, (void*)((PUCHAR)(Base)+pSec->VirtualAddress), pSec->Misc.VirtualSize, &pFound);
					if (NT_SUCCESS(status))
						o_PsSuspendThread = (p_PsSuspendThread)dereference((uintptr_t)pFound, 1);
					if (!o_PsSuspendThread)
					{
						status = SearchPattern(PsSuspendThread_pattern2, 0xCC, sizeof(PsSuspendThread_pattern2) - 1, (void*)((PUCHAR)(Base)+pSec->VirtualAddress), pSec->Misc.VirtualSize, &pFound);
						if (NT_SUCCESS(status))
							o_PsSuspendThread = (p_PsSuspendThread)dereference((uintptr_t)pFound, 1);
						if (!o_PsSuspendThread)
						{
							DbgPrint("[CVEAC-2020-0002] o_PsSuspendThread not found.");
							return Result;
						}
					}
					pFound = 0;
					status = SearchPattern(PsResumeThread_pattern, 0xCC, sizeof(PsResumeThread_pattern) - 1, (void*)((PUCHAR)(Base)+pSec->VirtualAddress), pSec->Misc.VirtualSize, &pFound);
					if (NT_SUCCESS(status))
						o_PsResumeThread = (p_PsResumeThread)dereference((uintptr_t)pFound, 1);
					if (!o_PsResumeThread)
					{
						status = SearchPattern(PsResumeThread_pattern2, 0xCC, sizeof(PsResumeThread_pattern2) - 1, (void*)((PUCHAR)(Base)+pSec->VirtualAddress), pSec->Misc.VirtualSize, &pFound);
						if (NT_SUCCESS(status))
							o_PsResumeThread = (p_PsResumeThread)dereference((uintptr_t)pFound, 1);
						if (!o_PsResumeThread)
						{
							DbgPrint("[CVEAC-2020-0002] o_PsResumeThread not found.");
							return Result;
						}
					}
				}
			}
			if (ImageCallBacks && ThreadCallBacks && o_PsSuspendThread && o_PsResumeThread)
			{
				DbgPrint("[CVEAC-2020-0002] PsSuspendThread found at 0x%llX", o_PsSuspendThread);
				DbgPrint("[CVEAC-2020-0002] PsResumeThread found at 0x%llX", o_PsResumeThread);
				DbgPrint("[CVEAC-2020-0002] ImageCallBacks found at 0x%llX", ImageCallBacks);
				DbgPrint("[CVEAC-2020-0002] ThreadCallBacks found at 0x%llX", ThreadCallBacks);
				DbgPrint("[CVEAC-2020-0002] All Addresses found. Bypass is ready!");
				Result = 1;
			}
		}
		else if (osInfo.dwMinorVersion == 3)
		{
			// Win8.1
			DbgPrint("[CVEAC-2020-0002] Windows 8.1 detected");
			Base = GetKernelBase();
			if (Base == 0)
			{
				DbgPrint("[CVEAC-2020-0002] GetKernelBase failed.");
				return Result;
			}
			Header = RtlImageNtHeader(Base);
			pFirstSec = (PIMAGE_SECTION_HEADER)(Header + 1);
			for (PIMAGE_SECTION_HEADER pSec = pFirstSec; pSec < pFirstSec + (Header->FileHeader.NumberOfSections); pSec++)
			{
				RtlInitAnsiString(&s1, "PAGE");
				RtlInitAnsiString(&s2, (PCCHAR)pSec->Name);
				if (RtlCompareString(&s1, &s2, TRUE) == 0)
				{
					UCHAR ImageCallBacks_pattern[] = "\x48\x8D\x3D\xCC\xCC\xCC\xCC\xBD\x40\x00\x00\x00\x89\x06";
					UCHAR ThreadCallBacks_pattern[] = "\x48\x8D\x1D\xCC\xCC\xCC\xCC\x41\xBF\x40\x00\x00\x00\x48\x8B\xCB";
					UCHAR PsSuspendThread_pattern[] = "\xE8\xCC\xCC\xCC\xCC\x8B\xF8\xBA\xCC\xCC\xCC\xCC\x48\x8B\x4C\x24\x68";
					UCHAR PsResumeThread_pattern[] = "\xE8\xCC\xCC\xCC\xCC\x8B\xF8\x83\xF8\x01\x75\xCC\x48\x8B\x8E\xCC\xCC\xCC\xCC";
					status = SearchPattern(ImageCallBacks_pattern, 0xCC, sizeof(ImageCallBacks_pattern) - 1, (void*)((PUCHAR)(Base)+pSec->VirtualAddress), pSec->Misc.VirtualSize, &pFound);
					if (NT_SUCCESS(status))
						ImageCallBacks = (PVOID*)dereference((uintptr_t)pFound, 3);
					if (!ImageCallBacks)
					{
						DbgPrint("[CVEAC-2020-0002] ImageCallBacks not found.");
						return Result;
					}
					pFound = 0;
					status = SearchPattern(ThreadCallBacks_pattern, 0xCC, sizeof(ThreadCallBacks_pattern) - 1, (void*)((PUCHAR)(Base)+pSec->VirtualAddress), pSec->Misc.VirtualSize, &pFound);
					if (NT_SUCCESS(status))
						ThreadCallBacks = (PVOID*)dereference((uintptr_t)pFound, 3);
					if (!ThreadCallBacks)
					{
						DbgPrint("[CVEAC-2020-0002] ThreadCallBacks not found.");
						return Result;
					}
					pFound = 0;
					status = SearchPattern(PsSuspendThread_pattern, 0xCC, sizeof(PsSuspendThread_pattern) - 1, (void*)((PUCHAR)(Base)+pSec->VirtualAddress), pSec->Misc.VirtualSize, &pFound);
					if (NT_SUCCESS(status))
						o_PsSuspendThread = (p_PsSuspendThread)dereference((uintptr_t)pFound, 1);
					if (!o_PsSuspendThread)
					{
						DbgPrint("[CVEAC-2020-0002] o_PsSuspendThread not found.");
						return Result;
					}
					pFound = 0;
					status = SearchPattern(PsResumeThread_pattern, 0xCC, sizeof(PsResumeThread_pattern) - 1, (void*)((PUCHAR)(Base)+pSec->VirtualAddress), pSec->Misc.VirtualSize, &pFound);
					if (NT_SUCCESS(status))
						o_PsResumeThread = (p_PsResumeThread)dereference((uintptr_t)pFound, 1);
					if (!o_PsResumeThread)
					{
						DbgPrint("[CVEAC-2020-0002] o_PsResumeThread not found.");
						return Result;
					}
				}
			}
			if (ImageCallBacks && ThreadCallBacks && o_PsSuspendThread && o_PsResumeThread)
			{
				DbgPrint("[CVEAC-2020-0002] PsSuspendThread found at 0x%llX", o_PsSuspendThread);
				DbgPrint("[CVEAC-2020-0002] PsResumeThread found at 0x%llX", o_PsResumeThread);
				DbgPrint("[CVEAC-2020-0002] ImageCallBacks found at 0x%llX", ImageCallBacks);
				DbgPrint("[CVEAC-2020-0002] ThreadCallBacks found at 0x%llX", ThreadCallBacks);
				DbgPrint("[CVEAC-2020-0002] All Addresses found. Bypass is ready!");
				Result = 1;
			}
		}
	}
	else if (osInfo.dwMajorVersion == 10)
	{
		// Win10
		DbgPrint("[CVEAC-2020-0002] Windows 10 detected");
		Base = GetKernelBase();
		if (Base == 0)
		{
			DbgPrint("[CVEAC-2020-0002] GetKernelBase failed.");
			return Result;
		}
		Header = RtlImageNtHeader(Base);
		pFirstSec = (PIMAGE_SECTION_HEADER)(Header + 1);
		for (PIMAGE_SECTION_HEADER pSec = pFirstSec; pSec < pFirstSec + (Header->FileHeader.NumberOfSections); pSec++)
		{
			RtlInitAnsiString(&s1, "PAGE");
			RtlInitAnsiString(&s2, (PCCHAR)pSec->Name);
			if (RtlCompareString(&s1, &s2, TRUE) == 0)
			{
				UCHAR ImageCallBacks_pattern[] = "\x48\x8D\x0D\xCC\xCC\xCC\xCC\x45\x33\xC0\x48\x8D\x0C\xD9\x48\x8B\xD7\xE8\xCC\xCC\xCC\xCC\x84\xC0\x0F\x84\xCC\xCC\xCC\xCC";
				UCHAR ThreadCallBacks_pattern[] = "\x48\x8D\x0D\xCC\xCC\xCC\xCC\x45\x33\xC0\x48\x8D\x0C\xD9\x48\x8B\xD7\xE8\xCC\xCC\xCC\xCC\x84\xC0\x74";
				// for older win10 versions 
				UCHAR ThreadCallBacks2_pattern[] = "\x48\x8D\x0D\xCC\xCC\xCC\xCC\x45\x33\xC0\x48\x8D\x0C\xD9\x48\x8B\xD7\xE8\xCC\xCC\xCC\xCC\x84\xC0\x75";
				UCHAR PsSuspendThread_pattern[] = "\xE8\xCC\xCC\xCC\xCC\x48\x8B\xD6\x48\x8B\xCD\xE8\xCC\xCC\xCC\xCC\x48\x8B\xF0";
				UCHAR PsResumeThread_pattern[] = "\xE8\xCC\xCC\xCC\xCC\x48\x8B\xD7\x48\x8B\xCD\xE8\xCC\xCC\xCC\xCC\xEB\xCC\xBB";
				// old win10 builds
				UCHAR PsSuspendThread3_pattern[] = "\xE8\xCC\xCC\xCC\xCC\x8B\xF8\xBA\xCC\xCC\xCC\xCC\x48\x8B\x4C\x24\x78";
				UCHAR PsResumeThread3_pattern[] = "\xE8\xCC\xCC\xCC\xCC\xBA\xCC\xCC\xCC\xCC\x48\x8B\x4C\x24\x78\xE8\xCC\xCC\xCC\xCC\x90";

				// for win10 ver 1903 and higher
				UCHAR PsSuspendThread2_pattern[] = "\xE8\xCC\xCC\xCC\xCC\x48\x8B\xD7\x48\x8B\xCE\xE8\xCC\xCC\xCC\xCC\x48\x8B\xF8";
				UCHAR PsResumeThread2_pattern[] = "\xE8\xCC\xCC\xCC\xCC\x48\x8B\xD7\x48\x8B\xCE\xE8\xCC\xCC\xCC\xCC\xCC\xCC\x49\x8B\xCE";

				status = SearchPattern(ImageCallBacks_pattern, 0xCC, sizeof(ImageCallBacks_pattern) - 1, (void*)((PUCHAR)(Base)+pSec->VirtualAddress), pSec->Misc.VirtualSize, &pFound);
				if (NT_SUCCESS(status))
					ImageCallBacks = (PVOID*)dereference((uintptr_t)pFound, 3);
				if (!ImageCallBacks)
				{
					DbgPrint("[CVEAC-2020-0002] ImageCallBacks not found.");
					return Result;
				}
				pFound = 0;
				status = SearchPattern(ThreadCallBacks_pattern, 0xCC, sizeof(ThreadCallBacks_pattern) - 1, (void*)((PUCHAR)(Base)+pSec->VirtualAddress), pSec->Misc.VirtualSize, &pFound);
				if (NT_SUCCESS(status))
					ThreadCallBacks = (PVOID*)dereference((uintptr_t)pFound, 3);
				if (!ThreadCallBacks)
				{
					DbgPrint("[CVEAC-2020-0002] ThreadCallBacks not found.Retrying...");
					status = SearchPattern(ThreadCallBacks2_pattern, 0xCC, sizeof(ThreadCallBacks2_pattern) - 1, (void*)((PUCHAR)(Base)+pSec->VirtualAddress), pSec->Misc.VirtualSize, &pFound);
					if (NT_SUCCESS(status))
						ThreadCallBacks = (PVOID*)dereference((uintptr_t)pFound, 3);
					if (!ThreadCallBacks)
					{
						DbgPrint("[CVEAC-2020-0002] ThreadCallBacks not found.");
						return Result;
					}

				}
				pFound = 0;
				status = SearchPattern(PsSuspendThread_pattern, 0xCC, sizeof(PsSuspendThread_pattern) - 1, (void*)((PUCHAR)(Base)+pSec->VirtualAddress), pSec->Misc.VirtualSize, &pFound);
				if (NT_SUCCESS(status))
					o_PsSuspendThread = (p_PsSuspendThread)dereference((uintptr_t)pFound, 1);
				if (!o_PsSuspendThread)
				{
					DbgPrint("[CVEAC-2020-0002] o_PsSuspendThread not found.Retrying...");
					status = SearchPattern(PsSuspendThread2_pattern, 0xCC, sizeof(PsSuspendThread2_pattern) - 1, (void*)((PUCHAR)(Base)+pSec->VirtualAddress), pSec->Misc.VirtualSize, &pFound);
					if (NT_SUCCESS(status))
						o_PsSuspendThread = (p_PsSuspendThread)dereference((uintptr_t)pFound, 1);
					if (!o_PsSuspendThread)
					{
						DbgPrint("[CVEAC-2020-0002] o_PsSuspendThread not found.Retrying...");
						status = SearchPattern(PsSuspendThread3_pattern, 0xCC, sizeof(PsSuspendThread3_pattern) - 1, (void*)((PUCHAR)(Base)+pSec->VirtualAddress), pSec->Misc.VirtualSize, &pFound);
						if (NT_SUCCESS(status))
							o_PsSuspendThread = (p_PsSuspendThread)dereference((uintptr_t)pFound, 1);
						if (!o_PsSuspendThread)
						{
							DbgPrint("[CVEAC-2020-0002] o_PsSuspendThread not found.");
							return Result;
						}
					}
				}
				pFound = 0;
				status = SearchPattern(PsResumeThread_pattern, 0xCC, sizeof(PsResumeThread_pattern) - 1, (void*)((PUCHAR)(Base)+pSec->VirtualAddress), pSec->Misc.VirtualSize, &pFound);
				if (NT_SUCCESS(status))
					o_PsResumeThread = (p_PsResumeThread)dereference((uintptr_t)pFound, 1);
				if (!o_PsResumeThread)
				{
					DbgPrint("[CVEAC-2020-0002] o_PsResumeThread not found.Retrying...");
					status = SearchPattern(PsResumeThread2_pattern, 0xCC, sizeof(PsResumeThread2_pattern) - 1, (void*)((PUCHAR)(Base)+pSec->VirtualAddress), pSec->Misc.VirtualSize, &pFound);
					if (NT_SUCCESS(status))
						o_PsResumeThread = (p_PsResumeThread)dereference((uintptr_t)pFound, 1);
					if (!o_PsResumeThread)
					{
						DbgPrint("[CVEAC-2020-0002] o_PsResumeThread not found.Retrying...");
						status = SearchPattern(PsResumeThread3_pattern, 0xCC, sizeof(PsResumeThread3_pattern) - 1, (void*)((PUCHAR)(Base)+pSec->VirtualAddress), pSec->Misc.VirtualSize, &pFound);
						if (NT_SUCCESS(status))
							o_PsResumeThread = (p_PsResumeThread)dereference((uintptr_t)pFound, 1);
						if (!o_PsResumeThread)
						{
							DbgPrint("[CVEAC-2020-0002] o_PsResumeThread not found.");
							return Result;
						}
					}
				}
			}
		}
		if (ImageCallBacks && ThreadCallBacks && o_PsSuspendThread && o_PsResumeThread)
		{
			DbgPrint("[CVEAC-2020-0002] PsSuspendThread found at 0x%llX", o_PsSuspendThread);
			DbgPrint("[CVEAC-2020-0002] PsResumeThread found at 0x%llX", o_PsResumeThread);
			DbgPrint("[CVEAC-2020-0002] ImageCallBacks found at 0x%llX", ImageCallBacks);
			DbgPrint("[CVEAC-2020-0002] ThreadCallBacks found at 0x%llX", ThreadCallBacks);
			DbgPrint("[CVEAC-2020-0002] All Addresses found. Bypass is ready!");
			Result = 1;
		}
	}

	if (Result == 0)
		return Result;

	if (!NT_SUCCESS(PsSetLoadImageNotifyRoutine(ImageRoutine)) ||
		!NT_SUCCESS(PsSetCreateProcessNotifyRoutine(ProcessRoutine, 0)))
	{
		VirtualizerStrEncryptStart();
		DbgPrint("[CVEAC-2020-0002] CallBack installation failed.");
		VirtualizerStrEncryptEnd();
		Result = 0;
		return Result;
	}
	ProcessPreOperation = 0;
	ProcessPostOperation = 0;
	ThreadPreOperation = 0;
	ThreadPostOperation = 0;
	VirtualizerStrEncryptEnd();
	VirtualizerEnd();
	return Result;
}

BOOLEAN UninitBypass()
{
	VirtualizerStart();
	VirtualizerStrEncryptStart();
	BOOLEAN Result = 1;
	if (ProcessPreOperation || ProcessPostOperation || ThreadPreOperation || ThreadPostOperation)
	{
		if (!Remove_Bypass())
		{
			DbgPrint("[CVEAC-2020-0002] WARNING : Failed to reset the callbacks");
			Result = 0;
		}
	}
	IsBypassEnabled = FALSE;
#if (RESTORE_ROUTINES == 1)
	if (RestoreThreadCallBack() == FALSE)
		DbgPrint("[CVEAC-2020-0002] WARNING : RestoreImageCallBack failed.");
	if (RestoreImageCallBack() == FALSE)
		DbgPrint("[CVEAC-2020-0002] WARNING : RestoreImageCallBack failed.");
#endif
	if (FilterAddr)
	{
		if (!RestoreMiniFilter())
		{
			DbgPrint("[CVEAC-2020-0002] Failed to restore the minifilter");
			Result = 0;
		}
	}
	if (!NT_SUCCESS(PsRemoveLoadImageNotifyRoutine(ImageRoutine)) ||
		!NT_SUCCESS(PsSetCreateProcessNotifyRoutine(ProcessRoutine, 1)))
	{
		DbgPrint("[CVEAC-2020-0002] Failed to remove the callbacks");
		Result = 0;
	}
	VirtualizerStrEncryptEnd();
	VirtualizerEnd();
	return Result;
}

VOID OnUnload(IN PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	VirtualizerStart();
	VirtualizerStrEncryptStart();

	UNICODE_STRING symLink;
	RtlInitUnicodeString(&symLink, dSymLinkBuffer);

	if (!NT_SUCCESS(IoDeleteSymbolicLink(&symLink)))
	{
		DbgPrint("[CVEAC-2020-0002] WARNING : IoDeleteSymbolicLink failed.");
	}
	if (pDeviceObject)
		IoDeleteDevice(pDeviceObject);
	if (!UninitBypass())
		DbgPrint("[CVEAC-2020-0002] WARNING : Failed to uninitialize the bypass.");
	VirtualizerStrEncryptEnd();
	VirtualizerEnd();

}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	VirtualizerStart();
	VirtualizerStrEncryptStart();
	NTSTATUS ntStatus = -1;
	UNICODE_STRING deviceNameUnicodeString, deviceSymLinkUnicodeString;

	RtlInitUnicodeString(&deviceNameUnicodeString, dNameBuffer);
	RtlInitUnicodeString(&deviceSymLinkUnicodeString, dSymLinkBuffer);

	DriverObject->DriverUnload = OnUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DeviceCreate;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DeviceClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceIoHandler;

	if (InitBypass() == 0)
	{
		DbgPrint("[CVEAC-2020-0002] InitBypass failed.");
		return ntStatus;
	}

	ntStatus = IoCreateDevice(DriverObject, 0, &deviceNameUnicodeString, FILE_DEVICE_UNKNOWN, FILE_DEVICE_UNKNOWN, FALSE, &pDeviceObject);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("[CVEAC-2020-0002] IoCreateDevice failed.");
		return ntStatus;
	}
	ntStatus = IoCreateSymbolicLink(&deviceSymLinkUnicodeString, &deviceNameUnicodeString);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("[CVEAC-2020-0002] IoCreateSymbolicLink failed.");
		return ntStatus;
	}
	//HideDriver(DriverObject);
	VirtualizerStrEncryptEnd();
	VirtualizerEnd();
	return ntStatus;
}

NTSTATUS DeviceCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	UNREFERENCED_PARAMETER(Irp);
	return STATUS_SUCCESS;
}

NTSTATUS DeviceClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	UNREFERENCED_PARAMETER(Irp);
	return STATUS_SUCCESS;
}

NTSTATUS DeviceIoHandler(PDEVICE_OBJECT DeviceObject, PIRP IRP)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	VirtualizerStart();
	VirtualizerStrEncryptStart();
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(IRP);
	IRP->IoStatus.Status = STATUS_SUCCESS;
	if (stack)
	{
		if (stack->Parameters.DeviceIoControl.IoControlCode == ctl_protectprocess)
		{
			PHIDEPROC_STRUCT buffer = (PHIDEPROC_STRUCT)IRP->AssociatedIrp.SystemBuffer;
			if (MmIsAddressValid(buffer))
				ProcessIdToProtect = buffer->pId;
			IRP->IoStatus.Information = sizeof(PHIDEPROC_STRUCT);
		}

		if (stack->Parameters.DeviceIoControl.IoControlCode == ctl_isenabled)
		{
			PIS_ENABLED_STRUCT buffer = (PIS_ENABLED_STRUCT)IRP->AssociatedIrp.SystemBuffer;
			if (MmIsAddressValid(buffer))
				buffer->IsEnabled = IsBypassEnabled;
			IRP->IoStatus.Information = sizeof(PIS_ENABLED_STRUCT);
		}
		if (stack->Parameters.DeviceIoControl.IoControlCode == ctl_getprocid)
		{
			PGETPROC_STRUCT buffer = (PGETPROC_STRUCT)IRP->AssociatedIrp.SystemBuffer;
			if (MmIsAddressValid(buffer))
				buffer->pId = pGameId;
			IRP->IoStatus.Information = sizeof(PGETPROC_STRUCT);
		}
	}

	IoCompleteRequest(IRP, IO_NO_INCREMENT);
	VirtualizerStrEncryptEnd();
	VirtualizerEnd();
	return IRP->IoStatus.Status;
}