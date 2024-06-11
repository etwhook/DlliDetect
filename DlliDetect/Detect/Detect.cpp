#include "Detect.h"

typedef VOID(NTAPI* t_LdrInitializeThunk)(
	PCONTEXT NormalContext,
	PVOID SystemArgument1,
	PVOID SystemArgument2

);
t_LdrInitializeThunk orgLdrInitializeThunk = NULL;


typedef NTSTATUS(WINAPI* t_NtQueryInformationThread) (
	HANDLE          ThreadHandle,
	THREADINFOCLASS ThreadInformationClass,
	PVOID           ThreadInformation,
	ULONG           ThreadInformationLength,
	PULONG          ReturnLength
);
t_NtQueryInformationThread fnNtQueryInformationThread = (t_NtQueryInformationThread)GetProcAddress(GetModuleHandleA("NTDLL"), "NtQueryInformationThread");


std::vector<LPCSTR> blackListedThreadStartAddresses { "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW", "LdrLoadDll" };

LPCSTR GetThreadStartAddressFunctionName(HANDLE process, DWORD64 threadStartAddress) {
	PVOID symbolBuffer = malloc(sizeof(SYMBOL_INFO) + MAX_SYM_NAME);

	RtlZeroMemory(symbolBuffer, sizeof(symbolBuffer));

	PSYMBOL_INFO symbolInfo = (PSYMBOL_INFO)symbolBuffer;
	symbolInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
	symbolInfo->MaxNameLen = MAX_SYM_NAME;

	if (!SymFromAddr(process, threadStartAddress, NULL, symbolInfo)) {
		return NULL;
	}

	return symbolInfo->Name;
}

PVOID GetThreadStartAddress(HANDLE thread) {
	PVOID startAddress;
	fnNtQueryInformationThread(thread, (THREADINFOCLASS)0x09, &startAddress, sizeof(PVOID), NULL);
	return startAddress;
}

VOID LdrInitializeThunkDetour(PCONTEXT NormalContext, PVOID SystemArgument1, PVOID SystemArgument2) {
	
	PVOID threadStartAddress = GetThreadStartAddress(GetCurrentThread());
	LPCSTR funcName = GetThreadStartAddressFunctionName(GetCurrentProcess(), (DWORD64)threadStartAddress);

	if (funcName) {

		for (LPCSTR& blacklistedName : blackListedThreadStartAddresses) {
			if (!strcmp(blacklistedName, funcName)) {
				PrintWarn("Possible DLL Injection Thread Detected  ( 0x%p ) ( %s )", threadStartAddress, funcName);
				TerminateThread(GetCurrentThread(), 0);
			}
		}

		PrintInfo("Thread Start Address: 0x%p ( %s )", threadStartAddress, funcName);
	}

	return orgLdrInitializeThunk(NormalContext, SystemArgument1, SystemArgument2);
}

BOOL InitLdrInitializeThunkHook() {

	if (MH_Initialize() != MH_OK) {
		PrintFail("Failed To Initialize MinHook.");
		return FALSE;
	}

	if (MH_CreateHookApi(L"NTDLL", "LdrInitializeThunk", LdrInitializeThunkDetour, (PVOID*)&orgLdrInitializeThunk) != MH_OK) {
		PrintFail("Failed To Initialize LdrInitializeThunk Hook.");
		return FALSE;
	}
	if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
		PrintFail("Failed To Enable Hooks.");
		return FALSE;
	}

	PrintOkay("Initialized DlliDetect Successfully.");

	return TRUE;
}