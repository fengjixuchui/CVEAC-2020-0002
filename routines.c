#include "main.h"
#include "options.h"

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
			if (ImageCallBack() == FALSE)
				DbgPrint("[CVEAC-2020-0002] WARNING : ImageCallBack failed");
			if (ThreadCallBack() == FALSE)
				DbgPrint("[CVEAC-2020-0002] WARNING : ThreadCallBack failed");
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
			if (!_stricmp(lpFileName, "EACGame.exe") ||
				strstr(lpFileName, "EACGame.exe"))
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