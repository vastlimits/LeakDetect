#include "QueuedFilesystemBackend.h"
#include "LeakFileStream.h"

#include <iostream>
#include <filesystem>
#include <unordered_set>

/// Assuming this is declared somewhere.
extern void LogMessage (const std::string& message);

class QueuedFilesystemBackend::Private
{
   friend class ::QueuedFilesystemBackend;
   
   std::unordered_set<uint32_t> known_stacktraces;
   std::shared_ptr<libLeak::LeakFileStream> writer;

   Private ()
   {
   }

   ~Private ()
   {
   }

   void initialize (DWORD pid)
   {
      // Attempt to create directory..
      auto directory = Private::GetSessionDirectory (pid);
      while (!std::filesystem::exists (directory))
      {
         std::filesystem::create_directories (directory);
         LogMessage ("Create directory " + directory.string ());
         if (!std::filesystem::exists(directory))
            Sleep (1000);
      }

      std::filesystem::path p (directory / "leak.dat");
      FILE* fp = nullptr;
      if (0 == fopen_s (&fp, p.string().c_str (), "wb"))
      {
         writer = std::make_shared<libLeak::LeakFileStream> (fp);
      }
      else
      {
         LogMessage ("Could not open target file " + p.string ());
      }
   }

   void WriteFileHeaderAndSession (DWORD pid)
   {
      if (!writer) 
         return;

      writer->WriteHeader ();
      writer->WriteSession (
         pid, 
         std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now ().time_since_epoch ()).count ());
   }

   void WriteEvent (const LEAKEVENT& event)
   {
      if (event.allocation != NULL)
      {
         // Write unique stacktraces once..
         uint32_t stacktrace_id = libLeak::CreateUniqueId (event.symbols);
         if (known_stacktraces.find (stacktrace_id) == known_stacktraces.end ())
         {
            writer->WriteStacktrace (stacktrace_id, event.symbols, event.allocation->TimestampEpochSeconds);
            known_stacktraces.insert (stacktrace_id);
         }

         // Serialize the allocation..
         writer->WriteAllocation (stacktrace_id, event.allocation);
      }
      else if (event.deallocation != NULL)
      {
         // Serialize the deallocation..
         writer->WriteDeallocation (event.deallocation);
      }
   }

   // Get current date/time, format is YYYY-MM-DD.HH:mm
   static const std::string time_str() 
   {
      time_t now = time(0);
      struct tm tstruct;
      char buf[80];
      localtime_s(&tstruct, &now);
      strftime(buf, sizeof(buf), "%Y-%m-%d.%H-%M", &tstruct);
      return buf;
   }

   static std::filesystem::path GetSessionDirectory (DWORD pid)
   {
      wchar_t path[MAX_PATH];
      memset (path, 0, sizeof (path));
      GetModuleFileName (NULL, path, MAX_PATH);

      std::wstring m (path);
      m = m.erase (m.find_last_of (L"\\") + 1);

      return std::filesystem::path (m) / "Logs" / (std::to_string (pid) + " - " + time_str ());
   }
};

QueuedFilesystemBackend::QueuedFilesystemBackend ()
   : mPrivate(new Private())
{
}

QueuedFilesystemBackend::~QueuedFilesystemBackend ()
{
   delete mPrivate;
   mPrivate = nullptr;
}

void QueuedFilesystemBackend::initialize (DWORD pid)
{
   // Initialize session writer..
   mPrivate->initialize (pid);

   // Initialize base class..
   __super::initialize (pid);
}

void QueuedFilesystemBackend::OnInitialized (DWORD pid)
{
   LogMessage ("Initialized QueuedFilesystemBackend for PID " + std::to_string (pid));
   mPrivate->WriteFileHeaderAndSession (pid);
}

void QueuedFilesystemBackend::OnProcessEvent (const LEAKEVENT& event)
{
   mPrivate->WriteEvent (event);
}