#include "Main.h"
#include <windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <strsafe.h>
#include <malloc.h>
#include <tchar.h>

HANDLE FindProcess(
	LPCWSTR ProcessName,
	BOOL OpenHandle,
	DWORD *pPid
)
{
	HANDLE hProcessSnap;
	PROCESSENTRY32W pe32;
	HANDLE result = INVALID_HANDLE_VALUE;

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
		return INVALID_HANDLE_VALUE;

	pe32.dwSize = sizeof(PROCESSENTRY32W);
	if (!Process32FirstW(hProcessSnap, &pe32)) {
		CloseHandle(hProcessSnap);
		return INVALID_HANDLE_VALUE;
	}

	do {
		if (lstrcmpW(ProcessName, pe32.szExeFile) == 0) {
			if (pPid != NULL)
				*pPid = pe32.th32ProcessID;

			if (OpenHandle) {
				result = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
				if (result == NULL)
					return INVALID_HANDLE_VALUE;
			}
			else
				result = (HANDLE)1;
			break;
		}
	} while (Process32NextW(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);

	return result;
}

HANDLE hFLux;
LPVOID FLUX_FUNC_LOC;
INT FLUX_BYTES_LEN;
BYTE *FLUX_DISABLE_BYTES;
BYTE *FLUX_ENABLE_BYTES;

DWORD ModFLux(CONST BYTE Bytes[])
{
	DWORD oldProtect;
	BOOL success;
	success = VirtualProtectEx(hFLux, FLUX_FUNC_LOC, FLUX_BYTES_LEN, PAGE_READWRITE, &oldProtect);

	if (!success)
		return GetLastError();

	success = WriteProcessMemory(hFLux, FLUX_FUNC_LOC, Bytes, FLUX_BYTES_LEN, NULL);

	if (!success)
		return GetLastError();

	success = VirtualProtectEx(hFLux, FLUX_FUNC_LOC, FLUX_BYTES_LEN, oldProtect, &oldProtect);

	if (!success)
		return GetLastError();

	return ERROR_SUCCESS;
}

DWORD EnableFLux()
{
	return ModFLux(FLUX_ENABLE_BYTES);
}

DWORD DisableFLux()
{
	return ModFLux(FLUX_DISABLE_BYTES);
}

DWORD InitializeFLuxApi(DWORD pid)
{
	DWORD fluxPid;
	if (pid == 0) {
		hFLux = FindProcess(L"flux.exe", TRUE, &fluxPid);

		if (hFLux == INVALID_HANDLE_VALUE)
			return ERROR_PROC_NOT_FOUND;
	} else
		fluxPid = pid;

	DWORD FLuxBase = 0;
	/* Find module base */ {
		HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
		MODULEENTRY32 me32;

		hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, fluxPid);

		if (hModuleSnap == INVALID_HANDLE_VALUE)
			return GetLastError();

		me32.dwSize = sizeof(MODULEENTRY32);

		if (!Module32FirstW(hModuleSnap, &me32))
			return GetLastError();

		while (FLuxBase == 0) {
			do {
				if (lstrcmpW(me32.szModule, L"flux.exe") == 0) {
					FLuxBase = (DWORD)me32.modBaseAddr;
					break;
				}
			} while (Module32Next(hModuleSnap, &me32));

			if (FLuxBase == 0)
				return ERROR_MOD_NOT_FOUND;
		}

		CloseHandle(hModuleSnap);
	}

	VS_FIXEDFILEINFO *version;
	/* Find version */ {
		WCHAR FLuxPath[MAX_PATH + 1] = { 0 };
		DWORD maxPath = MAX_PATH;
		if (QueryFullProcessImageNameW(hFLux, 0, FLuxPath, &maxPath) == 0) 
			return GetLastError();

		DWORD verHandle = 0;
		DWORD verSize = GetFileVersionInfoSizeW(FLuxPath, &verHandle);
		if (verSize == 0)
			return GetLastError();
		LPWSTR verData = alloca(verSize * sizeof(*verData));

		if (!GetFileVersionInfoW(FLuxPath, verHandle, verSize, verData))
			return GetLastError();

		UINT size;
		if (!VerQueryValueW(verData, L"\\", &version, &size))
			return ERROR_FILE_NOT_FOUND;

		if (size == 0)
			return ERROR_INVALID_FUNCTION;
	}

	if (version->dwFileVersionMS == 262186 || version->dwFileVersionMS == 262187) {
		// v4.42 / v4.43 detected
		FLUX_FUNC_LOC = (LPVOID)(FLuxBase + 0x743DA);
		FLUX_BYTES_LEN = 11;
		FLUX_ENABLE_BYTES = malloc(FLUX_BYTES_LEN);

		// possibly	883D
		//          ||||
		//	7564 A1 ???????? 85C0745B
		if (!ReadProcessMemory(hFLux, FLUX_FUNC_LOC, FLUX_ENABLE_BYTES, FLUX_BYTES_LEN, NULL)) 
			return GetLastError();

		FLUX_DISABLE_BYTES = malloc(FLUX_BYTES_LEN);
		memcpy_s(FLUX_DISABLE_BYTES, FLUX_BYTES_LEN, FLUX_ENABLE_BYTES, FLUX_BYTES_LEN);
		FLUX_DISABLE_BYTES[0] = 0x90;
		FLUX_DISABLE_BYTES[1] = 0x90;
		FLUX_DISABLE_BYTES[9] = 0x90;
		FLUX_DISABLE_BYTES[10] = 0x90;
	} else if (version->dwFileVersionMS == 196618) {
		// v3.10 detected
		FLUX_FUNC_LOC = (LPVOID)(FLuxBase + 0x5BE81);
		FLUX_BYTES_LEN = 7;
		FLUX_ENABLE_BYTES = malloc(FLUX_BYTES_LEN);
		memcpy_s(FLUX_ENABLE_BYTES, FLUX_BYTES_LEN, "\x8B\xF1\xE8\xE8\xE5\xFF\xFF", FLUX_BYTES_LEN);
		FLUX_DISABLE_BYTES = malloc(FLUX_BYTES_LEN);
		memcpy_s(FLUX_DISABLE_BYTES, FLUX_BYTES_LEN, "\x5E\xC2\x04\x00\x90\x90\x90", FLUX_BYTES_LEN);
	} else
		return ERROR_UNSUPPORTED_TYPE;

	return ERROR_SUCCESS;
}