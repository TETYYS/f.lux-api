#pragma once

#include <windows.h>

HANDLE FindProcess(
	LPCWSTR ProcessName,
	BOOL OpenHandle,
	DWORD *pPid
);

__declspec(dllexport) DWORD InitializeFLuxApi(DWORD pid);
__declspec(dllexport) DWORD EnableFLux();
__declspec(dllexport) DWORD DisableFLux();