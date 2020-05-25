#define _SILENCE_ALL_CXX17_DEPRECATION_WARNINGS
#include <codecvt>

#include <windows.h>

#pragma comment(lib, "detours.lib")
#pragma comment(lib, "syelog.lib")

#include <detours.h>
#include <syelog.h>

#include "libLeak.h"

static LONG gTlsIndent = -1;
static LONG gTlsThread = -1;
static LONG gTlsThreadCount = 0;
static DWORD gProcessId = 0;
static std::wstring gInterruptContinueEvent;
static std::string gEventStart;
static std::string gEventStop;

HANDLE hEventInterrupt         = NULL;        // Handle to event if we interrupt.
HANDLE hEventInterruptContinue = NULL;        // Handle to event if we are interrupted to wait for resume signal.
HANDLE hEventStartConfirm = NULL;
HANDLE hEventStopConfirm = NULL;
HANDLE hThreadControllerStart  = NULL;        // Handle to controller thread which listens to start signal.
HANDLE hThreadControllerStop   = NULL;        // Handle to controller thread which listens to stop signal.
volatile BOOL ProfilingEnabled = FALSE;       // Indicates wether the profiling interrupts are active or not.
CRITICAL_SECTION SyncSection;                 // Synchronize allocation / release access.

__declspec(dllexport) libLeak::ANALYZER_METADATA Metadata;

//
// Detoured API Functions
//
#ifdef _WIN64
LPVOID (WINAPI *Real_HeapAlloc)(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes) = HeapAlloc;
#else
LPVOID (WINAPI *Real_HeapAlloc)(HANDLE hHeap, DWORD dwFlags, DWORD dwBytes) = HeapAlloc;
#endif
BOOL (WINAPI *Real_HeapFree)(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem) = HeapFree;

/// Inlined function to ensure that IPC communication is alive.
/// This method may deadlock the instrumented process if it constantly fails.
/// The monitoring process creates the given event.
__forceinline void EnsureIPC ()
{
   // Ensure the handle is valid.
   while (hEventInterruptContinue == NULL)
   {
      // Use OpenEventW here because OpenEventA would allocate memory and that would result
      // in a bad deadlock.
      hEventInterruptContinue = OpenEventW (SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, gInterruptContinueEvent.c_str());
      if (hEventInterruptContinue == NULL)
         Sleep (100);
   }
}

///
/// Instrumentation function.
/// Inlined to make sure to not grow the callstack by our detoured functions.
__forceinline void InstrumentAllocation (
   libLeak::InstrumentType type, 
   LPVOID ptr, 
   DWORD size)
{
   // Prepare metadata for the watcher process.
   RtlCaptureContext (&Metadata.Context);
   Metadata.Type = (DWORD)type;
   Metadata.Pointer = (intptr_t)ptr;
   Metadata.Size = size;

   // Notify the watcher process.
   SetEvent (hEventInterrupt);

   // Wait for resume signal.
   WaitForSingleObject (hEventInterruptContinue, INFINITE);
}

///
/// InstrumentDeallocation function.
/// Inlined to make sure to not grow the callstack by our detoured functions.
__forceinline void InstrumentDeallocation (
   libLeak::InstrumentType type,
   LPVOID ptr)
{
   // Prepare metadata for the watcher process.
   RtlCaptureContext (&Metadata.Context);
   Metadata.Type = (DWORD)type;
   Metadata.Pointer = (intptr_t)ptr;
   Metadata.Size = 0;

   // Notify the watcher process.
   SetEvent (hEventInterrupt);

   // Wait for resume signal.
   WaitForSingleObject (hEventInterruptContinue, INFINITE);
}

/// Detoured HeapAlloc API function.
#ifdef _WIN64
LPVOID WINAPI uberHeapAlloc (HANDLE hHeap, DWORD dwFlags, DWORD dwBytes)
#else
LPVOID WINAPI uberHeapAlloc (HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes)
#endif
{
   LPVOID rv = 0;

   EnterCriticalSection (&SyncSection);
   
   // Ensure IPC communication is alive.
   // That may cause a deadlock if the watcher process is not alive.
   EnsureIPC ();

   __try {
      rv = Real_HeapAlloc (hHeap, dwFlags, dwBytes);
      if (ProfilingEnabled && rv)
      {
         // Do analysis if enabled.
         InstrumentAllocation (libLeak::InstrumentType::Allocation, rv, (SIZE_T)dwBytes);
      }
   }
   __finally {

      LeaveCriticalSection (&SyncSection);
   }
   return rv;
}

/// Detoured HeapFree API function.
BOOL WINAPI uberHeapFree (HANDLE hHeap, DWORD dwFlags, LPVOID lpMem)
{
   BOOL result = FALSE;

   EnterCriticalSection (&SyncSection);

   // Ensure IPC communication is alive.
   // That may cause a deadlock if the watcher process is not alive.
   EnsureIPC ();

   __try 
   {
      result = Real_HeapFree (hHeap, dwFlags, lpMem);
      if (ProfilingEnabled && result)
      {
         // Do analysis if successfull.
         InstrumentDeallocation (libLeak::InstrumentType::Deallocation, lpMem);
      }
   }
   __finally 
   {
      LeaveCriticalSection (&SyncSection);
   }

   return result;
}

/// Enables Instrumentation.
void StartInstrumentation ()
{
   EnterCriticalSection (&SyncSection);
   {
      ProfilingEnabled = TRUE;
      SetEvent (hEventStartConfirm);
   }
   LeaveCriticalSection (&SyncSection);
}

/// Disables Instrumentation.
void StopInstrumentation ()
{
   EnterCriticalSection (&SyncSection);
   {
      ProfilingEnabled = FALSE;
      SetEvent (hEventStopConfirm);
   }
   LeaveCriticalSection (&SyncSection);
}

/// Process remote events.
void ServiceControl (const std::string* eventName)
{
   if (eventName == nullptr ||
      eventName->empty ())
   {
      return;
   }

   if (strcmp (eventName->c_str(), gEventStart.c_str()) == 0)
   {
      StartInstrumentation ();
   }
   else if (strcmp (eventName->c_str(), gEventStop.c_str()) == 0)
   {
      StopInstrumentation ();
   }
}

/// Wrapper thread for handling a specific remote event.
DWORD WINAPI ControllerThread (LPVOID lpParameter)
{
   std::string* event = (std::string*)lpParameter;

   HANDLE hEvent = NULL;

   // Attempt to open the event.
   // May take some time if the watching process is not started yet.
   do
   {
      hEvent = OpenEventA (SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, event->c_str());
      if (hEvent != NULL)
         break;

      Sleep (100);

   } while (true);

   DWORD result;

   // Infinite threading loop.
   for (;;)
   {
      result = WaitForSingleObject (hEvent, INFINITE);
      if (result == WAIT_OBJECT_0)
      {
         ServiceControl (event);
      }
      else
      {
         // That should not happen.
         break;
      }
   }

   CloseHandle (hEvent);
   delete event;
   return 0;
}

/// Applies the detoured functions.
LONG AttachDetours (VOID)
{
   DetourTransactionBegin ();
   DetourUpdateThread (GetCurrentThread ());

   DetourAttach (&(PVOID&)Real_HeapAlloc, uberHeapAlloc);
   DetourAttach (&(PVOID&)Real_HeapFree, uberHeapFree);

   return DetourTransactionCommit ();
}

/// Removes the detoured functions.
LONG DetachDetours (VOID)
{
   DetourTransactionBegin ();
   DetourUpdateThread (GetCurrentThread ());

   DetourDetach (&(PVOID&)Real_HeapAlloc, uberHeapAlloc);
   DetourDetach (&(PVOID&)Real_HeapFree, uberHeapFree);

   return DetourTransactionCommit ();
}

/// Attaches to a thread. Currently just incrementing
/// thread counters.
BOOL ThreadAttach (HMODULE hDll)
{
   (void)hDll;

   if (gTlsIndent >= 0) {
      TlsSetValue(gTlsIndent, (PVOID)0);
   }

   if (gTlsThread >= 0) {
      LONG nThread = InterlockedIncrement(&gTlsThreadCount);
      TlsSetValue(gTlsThread, (PVOID)(LONG_PTR)nThread);
   }
   return TRUE;
}

/// Detaches from a thread.
BOOL ThreadDetach (HMODULE hDll)
{
   (void)hDll;

   if (gTlsIndent >= 0) {
      TlsSetValue(gTlsIndent, (PVOID)0);
   }
   
   if (gTlsThread >= 0) {
      TlsSetValue(gTlsThread, (PVOID)0);
   }
   return TRUE;
}

/// Initializes IPC eevents.
BOOL InitializeEvents ()
{
   std::string event = libLeak::ReplaceEventName (libLeak::VL_MEMORY_EVENT_INTERRUPT, gProcessId);
   hEventInterrupt = CreateEventA (NULL, FALSE, FALSE, event.c_str());
   if (hEventInterrupt == NULL)
   {
      return FALSE;
   }

   event = libLeak::ReplaceEventName (libLeak::VL_MEMORY_EVENT_START_CONFIRM, gProcessId);
   hEventStartConfirm = CreateEventA (NULL, FALSE, FALSE, event.c_str());
   if (hEventStartConfirm == NULL)
   {
      return FALSE;
   }

   event = libLeak::ReplaceEventName (libLeak::VL_MEMORY_EVENT_STOP_CONFIRM, gProcessId);
   hEventStopConfirm = CreateEventA (NULL, FALSE, FALSE, event.c_str());
   if (hEventStopConfirm == NULL)
   {
      return FALSE;
   }

   event = libLeak::ReplaceEventName (libLeak::VL_MEMORY_EVENT_REMOTE_START, gProcessId);
   hThreadControllerStart = CreateThread (NULL, NULL, ControllerThread, (LPVOID)new std::string(event), 0, NULL);
   if (hThreadControllerStart == NULL)
   {
      return FALSE;
   }

   event = libLeak::ReplaceEventName (libLeak::VL_MEMORY_EVENT_REMOTE_STOP, gProcessId);
   hThreadControllerStop = CreateThread (NULL, NULL, ControllerThread, (LPVOID)new std::string(event), 0, NULL);
   if (hThreadControllerStop == NULL)
   {
      TerminateThread (hThreadControllerStart, 0);
      CloseHandle (hThreadControllerStart);
      return FALSE;
   }

   event.clear ();
   event.shrink_to_fit ();
   return TRUE;
}

/// Attaches to this process and initializes detours.
BOOL ProcessAttach (HMODULE hDll)
{
   gTlsIndent = TlsAlloc();
   gTlsThread = TlsAlloc();

   // Initialize critical section.
   InitializeCriticalSection (&SyncSection);

   // Initialize PID
   gProcessId = GetCurrentProcessId ();
   std::string sname = libLeak::ReplaceEventName (libLeak::VL_MEMORY_EVENT_REMOTE_INTERRUPT_CONTINUE, gProcessId);
   std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
   gInterruptContinueEvent = converter.from_bytes(sname);

   gEventStart = libLeak::ReplaceEventName (libLeak::VL_MEMORY_EVENT_REMOTE_START, gProcessId);
   gEventStop = libLeak::ReplaceEventName (libLeak::VL_MEMORY_EVENT_REMOTE_STOP, gProcessId);

   // Initialize interrupt event..
   if (!InitializeEvents ())
      return FALSE;

   LONG error = AttachDetours ();
   if (error != NO_ERROR) {
      TerminateThread (hThreadControllerStart, 0);
      TerminateThread (hThreadControllerStop, 0);
      CloseHandle (hThreadControllerStart);
      CloseHandle (hThreadControllerStop);
      return FALSE;
   }

   return ThreadAttach(hDll);
}

/// Unloads all detours and allocated resources.
BOOL ProcessDetach (HMODULE hDll)
{
   ThreadDetach(hDll);

   DetachDetours ();

   if (hThreadControllerStart)
   {
      TerminateThread (hThreadControllerStart, 0);
      CloseHandle (hThreadControllerStart);
   }

   if (hThreadControllerStop)
   {
      TerminateThread (hThreadControllerStop, 0);
      CloseHandle (hThreadControllerStop);
   }

   DeleteCriticalSection (&SyncSection);

   if (gTlsIndent >= 0) 
   {
      TlsFree(gTlsIndent);
   }

   if (gTlsThread >= 0) 
   {
      TlsFree(gTlsThread);
   }

   return TRUE;
}

///
/// Entrypoint
///
BOOL APIENTRY DllMain(HINSTANCE hModule, DWORD dwReason, PVOID lpReserved)
{
   UNREFERENCED_PARAMETER (hModule);
   UNREFERENCED_PARAMETER (lpReserved);

   if (DetourIsHelperProcess ()) {
      return TRUE;
   }

   switch (dwReason)
   {
   case DLL_PROCESS_ATTACH:
      DetourRestoreAfterWith ();
      return ProcessAttach (hModule);
   case DLL_THREAD_ATTACH:
      return ThreadDetach (hModule);
   case DLL_THREAD_DETACH:
      return ThreadAttach (hModule);
   case DLL_PROCESS_DETACH:
      return ProcessDetach (hModule);
      break;
   }
   return TRUE;
}
