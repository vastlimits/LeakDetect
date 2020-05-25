#pragma once

HMODULE WINAPI GetRemoteModuleHandle (HANDLE hProcess, LPCSTR lpModuleName);
FARPROC WINAPI GetRemoteProcAddress (HANDLE hProcess, HMODULE hModule, LPCSTR lpProcName, UINT Ordinal = 0, BOOL UseOrdinal = FALSE);
HRESULT CaptureStackTrace (__in CONST PCONTEXT Context, __in HANDLE RemoteProcess, __in libLeak::PSTACKTRACE StackTrace);