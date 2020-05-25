#define _SILENCE_ALL_CXX17_DEPRECATION_WARNINGS

#include <iostream>
#include <string>
#include <chrono>
#include <mutex>

#include <codecvt>

#include "libLeak.h"
#include "LeakClient.h"
#include "QueuedFilesystemBackend.h"
#include "RemoteProcessAPI.h"

#include <TlHelp32.h>

/// Global variables
bool bExitApplication = false;

// Get current date/time, format is YYYY-MM-DD.HH:mm:ss
const std::string time_str() 
{
   time_t now = time(0);
   struct tm tstruct;
   char buf[80];
   localtime_s(&tstruct, &now);
   strftime(buf, sizeof(buf), "%Y-%m-%d.%X", &tstruct);
   return buf;
}

__forceinline uint64_t now () { return (uint64_t)std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now ().time_since_epoch ()).count(); }

// Synchronized logging routine.
std::mutex log_mutex;

void LogMessage (const std::string& message)
{
   const std::lock_guard<std::mutex> lock(log_mutex);
   std::cout << time_str() << ": " << message << std::endl;
}

///
/// ConsoleLeakClient
/// 
class ConsoleLeakClient : public LeakClient
{
   LeakBackend* const backend;
   HANDLE hRemoteProcessHandle = NULL;
   PVOID hRemoteSymbol = NULL;

public:
   ConsoleLeakClient (LeakBackend* const ptr)
      : backend(ptr)
   {
   }

   virtual ~ConsoleLeakClient () override
   {
      if (hRemoteProcessHandle)
      {
         CloseHandle (hRemoteProcessHandle);
      }
   }

   void OnEventCreated (const std::string& eventName) override
   {
      LogMessage ("Created event " + eventName);
   }
   
   void OnEventCreateError (const std::string& eventName) override 
   {
      LogMessage ("Could not create event " + eventName);
   }

   void OnInjectLibrary (DWORD processId) override
   {
      LogMessage ("Library was injected into process " + std::to_string (processId));
   }
   
   void OnInjectLibraryError (DWORD processId) override
   {
      LogMessage ("Could not inject library into process " + std::to_string (processId));
   }

   void OnEventOpened (const std::string& eventName) override
   {
      LogMessage ("Opened event " + eventName);
   }

   void OnProfilingStarted () override
   { 
      LogMessage ("Profiling started.");
   }
   
   void OnProfilingStopped () override
   {
      LogMessage ("Profiling stopped.");
   }

   void InstrumentAllocation (libLeak::PANALYZER_METADATA metadata)
   {
      libLeak::ALLOCATION_EVENT* event = new libLeak::ALLOCATION_EVENT ();
      memset (event, 0, sizeof (libLeak::ALLOCATION_EVENT));
      
      if (S_OK != CaptureStackTrace (
         &metadata->Context, 
         hRemoteProcessHandle, 
         &event->Stacktrace))
      {
         // Could not grab the stacktrace.
         delete event;
         event = nullptr;
         return;
      }

      event->Pointer = metadata->Pointer;
      event->Size = metadata->Size;
      event->TimestampEpochSeconds = now ();
      backend->push (event);
   }

   void InstrumentDeallocation (libLeak::PANALYZER_METADATA metadata)
   {
      libLeak::DELLOCATION_EVENT* event = new libLeak::DELLOCATION_EVENT ();
      memset (event, 0, sizeof (libLeak::DELLOCATION_EVENT));
      
      event->Pointer = metadata->Pointer;
      event->TimestampEpochSeconds = now ();
      backend->push (event);
   }

   ///
   /// The remote process is waiting for this function to return.
   /// Try to minimize heavy operations.
   ///
   /// Collect all required information and queue to it to some
   /// post-processing logic.
   ///
   void OnSignal (DWORD pid) override
   {
      // The actual instance is static and can be used
      // over and over again since this is single-threaded.
      static libLeak::ANALYZER_METADATA metadata;
      
      // Initialize the metadata with zeroes.
      memset (&metadata, 0, sizeof(libLeak::ANALYZER_METADATA));
      
      // Reading the metadata should not really failure in production.
      if (!ReadMetadata (&metadata, pid)) return;

      switch (metadata.Type)
      {
      case (int)libLeak::InstrumentType::Allocation:
         InstrumentAllocation (&metadata);
         break;
      case (int)libLeak::InstrumentType::Deallocation:
         InstrumentDeallocation (&metadata);
         break;
      default:
         break;
      }
   }

   void OnTimeout (DWORD timeoutMs) override
   {
      UNREFERENCED_PARAMETER (timeoutMs);
      
      backend->signal_timeout ();
   }

private:
   ///
   /// Reads the exported metadata structure from the remote process.
   /// This requires a couple of pre-requirements:
   /// - Opened handle with PROCESS_VM_READ rights
   /// - LeakDetect.dll loaded to the target process.
   /// - The exported symbol 'Metadata'.
   ///
   BOOL ReadMetadata (libLeak::PANALYZER_METADATA metadata, DWORD pid)
   {
      // Open the handle on first usage.
      if (hRemoteProcessHandle == NULL)
      {
         // Technically do not require PROCESS_ALL_ACCESS.
         // But PROCESS_VM_READ is not enough; so .. this is the easy peasy solution.
         // Also, this handle is used to grab the Stacktrace.
         hRemoteProcessHandle = OpenProcess (PROCESS_ALL_ACCESS, FALSE, pid);
         if (hRemoteProcessHandle == NULL)
            return FALSE;

         backend->SetRemoteProcessHandle (hRemoteProcessHandle);
      }

      // Get the exported symbol address.
      if (hRemoteSymbol == NULL)
      {
         std::string module = GetLeakDetectFileName ();
         HMODULE hModule = GetRemoteModuleHandle(hRemoteProcessHandle, module.c_str());
         if (hModule != NULL)
         {
            hRemoteSymbol = (FARPROC)GetRemoteProcAddress (hRemoteProcessHandle, hModule, "Metadata");
         }

         if (hRemoteSymbol == NULL)
            return FALSE;
      }

      return ReadProcessMemory (
         hRemoteProcessHandle, 
         (LPCVOID)hRemoteSymbol, 
         (LPVOID)metadata, 
         sizeof (libLeak::ANALYZER_METADATA), NULL);
   }
};

/// Custom Control Handler to gracefully shutdown.
BOOL WINAPI ConsoleBreakRoutine (DWORD dwControlType)
{
   UNREFERENCED_PARAMETER (dwControlType);
   bExitApplication = true;
   return TRUE;
}

/// Case-insensitive string comparison
bool iequals(const std::string& a, const std::string& b)
{
   return std::equal(a.begin(), a.end(), b.begin(), b.end(), [](char a, char b) { return tolower(a) == tolower(b); });
}

/// Finds a given process by name.
DWORD lookup_process (const char* process)
{
   DWORD pid = atoi (process);
   if (pid != 0)
   {
      return pid;
   }

   std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;

   // Most likely a process name was passed.
   PROCESSENTRY32 processInfo;
   processInfo.dwSize = sizeof(processInfo);
   HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
   if (processesSnapshot != INVALID_HANDLE_VALUE)
   {
      const std::string given_process = std::string (process);
      for (BOOL ok = Process32First(processesSnapshot, &processInfo); ok; ok = Process32Next(processesSnapshot, &processInfo))
      {
         std::string converted = converter.to_bytes(std::wstring (processInfo.szExeFile));
         if (iequals(converted, given_process))
         {
            CloseHandle (processesSnapshot);
            return processInfo.th32ProcessID;
         }
      }
      CloseHandle(processesSnapshot);
   }

   return 0;
}

///
/// Leak Detector entry point.
///
/// Injecting into existing remote process.
/// ---------------------------------------------------------------------------
/// LeakMonitor.X86.exe --inject PID [where PID is the remote pid]
///
/// Loading into existing remote process [1]
/// ---------------------------------------------------------------------------
///  LeakMonitor.X86.exe
///
/// [1] >> the remote process must have loaded the LeakDetect.X86.dll already.
/// 
/// Note
/// ---------------------------------------------------------------------------
/// To detect memory leaks in x64 processes, use the binaries 
///  - LeakDetect.X64.dll
///  - LeakMonitor.X64.exe
///  
int main(int argc, char** argv)
{
   LEAKCLIENT_SETTINGS settings;
   memset (&settings, 0, sizeof (LEAKCLIENT_SETTINGS));

   // Process command line arguments.
   for (int i = 0; i < argc; i++)
   {
      const char* argument = argv[i];
      if (strcmp (argument, "--inject") == 0 && (i + 1) < argc)
      {
         settings.inject = true;
         settings.pid = lookup_process ((argv[i + 1]));
      }
      else if (strcmp (argument, "--pid") == 0 && (i + 1) < argc)
      {
         settings.pid = lookup_process ((argv[i + 1]));
      }
   }

   // Make sure the PID is not zero.
   if (settings.pid == 0)
      return 1;

   // Initialize the backend (serializer)
   QueuedFilesystemBackend* backend = new QueuedFilesystemBackend ();
   backend->initialize (settings.pid);

   ConsoleLeakClient client(backend);
   if (!client.bootstrap (settings))
   {
      std::cerr << "Could not bootstrap LeakClient IPC." << std::endl;
      return 1;
   }

   // Setup console CTRL+c action.
   SetConsoleCtrlHandler (ConsoleBreakRoutine, TRUE);

   // Run the LeakClient main loop.
   client.run_mainloop (bExitApplication);

   // Wait for the serializer to finish. (happens during delete)
   backend->join ();

   delete backend;
   backend = nullptr;

   return 0;
}
