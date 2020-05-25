#include <string>

#include <Windows.h>

///
/// Injects the given library to the remote process.
/// hProcess      Must be opened with PROCESS_ALL_ACCESS
/// memory        The remote address of the written dll buffer. Make sure to free this memory
///               when the DLL is finished doing work, otherwise the path is leaked in a memory page.
///
/// Returns ERROR_NOT_FOUND                  if kernel32.dll or LoadLibraryA is not available.
/// Returns ERROR_NOT_ALLOWED_ON_SYSTEM_FILE if a memory operation did not succeed, most likely
///                                          happens if the handle was not opened with correct access rights.
/// Returns ERROR_SUCCESS                    if the injection succeeded.
///
///
DWORD Inject (HANDLE hProcess, const std::string& dll, LPVOID& memory)
{
   // kernel32 shares the *same* base address in all processes.
   // This makes it easy to retreive the LoadLibraryA routine address as we can just
   // query the address from this process.
   HMODULE hModule = GetModuleHandle (L"kernel32.dll");
   if (hModule == NULL)
      return ERROR_NOT_FOUND;

   LPVOID pLoadLibrary = (LPVOID)GetProcAddress (hModule, "LoadLibraryA");
   if (pLoadLibrary == NULL)
      return ERROR_NOT_FOUND;

   // Allocate new memory region in process target address space.
   memory = (LPVOID)VirtualAllocEx (hProcess, NULL, dll.size (), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
   if (memory == NULL)
      return ERROR_NOT_ALLOWED_ON_SYSTEM_FILE;

   // Write the dll path to the newly allocated memory.
   if (!WriteProcessMemory (hProcess, memory, (LPCVOID)dll.c_str (), dll.size (), NULL))
      return ERROR_NOT_ALLOWED_ON_SYSTEM_FILE;

   // Inject the library.
   // Creates a remote thread with LoadLibraryA as entry point and the written dll buffer as argument.
   HANDLE hRemoteThread = CreateRemoteThread (hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, memory, NULL, NULL);
   if (hRemoteThread == NULL)
      return ERROR_NOT_ALLOWED_ON_SYSTEM_FILE;

   return ERROR_SUCCESS;
}