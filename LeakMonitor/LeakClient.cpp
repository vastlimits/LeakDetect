#include "LeakClient.h"

#include <string>
#include <iostream>

#include "libLeak.h"

#include <Psapi.h>

///
/// WriteEvent class
/// This class creates wraps a Windows Event (CreateEvent)
///
class WriteEvent {
public:
   WriteEvent (const std::string& name)
      : mEventName (name)
      , mHandle(NULL)
   {
   }
   
   ~WriteEvent ()
   {
      if (mHandle)
      {
         CloseHandle (mHandle);
      }
   }

   void signal ()
   {
      SetEvent (mHandle);
   }

   bool create ()
   {
      mHandle = CreateEventA (NULL, FALSE, FALSE, mEventName.c_str());
      return mHandle != NULL;
   }

   const std::string& GetName () const { return mEventName; }

private:
   std::string mEventName;
   HANDLE mHandle;
};

///
/// ReadEvent class
/// This class creates wraps a Windows Event (OpenEvent)
///
class ReadEvent {
public:
   ReadEvent (const std::string& name)
      : mEventName (name)
      , mHandle(NULL)
   {
   }
   
   ~ReadEvent ()
   {
      if (mHandle)
      {
         CloseHandle (mHandle);
      }
   }
   
   bool wait_for_signal_timeout (DWORD timeout)
   {
      return WaitForSingleObject (mHandle, timeout) == WAIT_OBJECT_0;
   }


   void wait_for_signal ()
   {
      WaitForSingleObject (mHandle, INFINITE);
   }

   void wait_until_opened ()
   {
      while (!open())
         Sleep (100);
   }

   const std::string& GetName () const 
   {
      return mEventName;
   }

private:
   bool open ()
   {
      mHandle = OpenEventA (SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, mEventName.c_str());
      return mHandle != NULL;
   }

   std::string mEventName;
   HANDLE mHandle;
};

// Forwarded from Inject.cpp
DWORD Inject (HANDLE hProcess, const std::string& dll, LPVOID& memory);

///
/// Injects the LeakDetect library to the target process.
/// Required, if starting the monitor with live injection, otherwise
/// the target process must load the library manually.
bool Inject (DWORD processId, const std::string& dll)
{
   HANDLE hProcess = OpenProcess (PROCESS_ALL_ACCESS, FALSE, processId);
   if (hProcess == NULL)
   {
      std::cerr << "Could not open target process " 
         << std::to_string (processId) 
         << " with process access mask PROCESS_ALL_ACCESS" << std::endl;

      return 1;
   }

   // We ignore the target process memory leak here.
   // There is no real requirement while inspecting,
   // to release this dll path from the remote address space.
   LPVOID pDllPathRemoteMemory = NULL;
   DWORD result = Inject (hProcess, dll, pDllPathRemoteMemory);
   if (result == ERROR_NOT_FOUND || result == ERROR_NOT_ALLOWED_ON_SYSTEM_FILE)
   {
      std::cerr << "Critical system error while injecting the dll." << std::endl;
   }
   else if (result != ERROR_SUCCESS)
   {
      std::cerr << "Unknown system error while injecting the dll." << std::endl;
   }

   if (hProcess)
   {
      CloseHandle (hProcess);
   }

   return result == ERROR_SUCCESS;
}

///
/// LeakClient::Private
///
class LeakClient::Private
{
   friend class ::LeakClient;
   ::LeakClient* qptr;
   DWORD pid;
   std::shared_ptr<WriteEvent> ipcEventInterruptConfirm;
   std::shared_ptr<WriteEvent> ipcEventStart;
   std::shared_ptr<WriteEvent> ipcEventStop;
   std::shared_ptr<ReadEvent> ipcEventInterrupt;
   std::shared_ptr<ReadEvent> ipcEventStartConfirm;
   std::shared_ptr<ReadEvent> ipcEventStopConfirm;

   Private (LeakClient* q)
      : qptr(q)
      , pid(0)
   {
   }

   ~Private ()
   {
      qptr = nullptr;
   }

   bool bootstrap (const LEAKCLIENT_SETTINGS& settings)
   {
      pid = settings.pid;
      ipcEventInterruptConfirm = std::make_shared<WriteEvent> (libLeak::ReplaceEventName(libLeak::VL_MEMORY_EVENT_REMOTE_INTERRUPT_CONTINUE, pid));
      ipcEventStart = std::make_shared<WriteEvent> (libLeak::ReplaceEventName(libLeak::VL_MEMORY_EVENT_REMOTE_START, pid));
      ipcEventStop = std::make_shared<WriteEvent> (libLeak::ReplaceEventName(libLeak::VL_MEMORY_EVENT_REMOTE_STOP, pid));
      ipcEventInterrupt = std::make_shared<ReadEvent> (libLeak::ReplaceEventName(libLeak::VL_MEMORY_EVENT_INTERRUPT, pid));
      ipcEventStartConfirm = std::make_shared<ReadEvent> (libLeak::ReplaceEventName(libLeak::VL_MEMORY_EVENT_START_CONFIRM, pid));
      ipcEventStopConfirm = std::make_shared<ReadEvent> (libLeak::ReplaceEventName(libLeak::VL_MEMORY_EVENT_STOP_CONFIRM, pid));

      if (!ipcEventInterruptConfirm->create ())
      {
         qptr->OnEventCreateError (ipcEventInterruptConfirm->GetName ());
         return false;
      }
      else
      {
         qptr->OnEventCreated (ipcEventInterruptConfirm->GetName ());
      }

      if (!ipcEventStart->create ())
      {
         qptr->OnEventCreateError (ipcEventStart->GetName ());
         return false;
      }
      else
      {
         qptr->OnEventCreated (ipcEventStart->GetName ());
      }

      if (!ipcEventStop->create ())
      {
         qptr->OnEventCreateError (ipcEventStop->GetName ());
         return false;
      }
      else
      {
         qptr->OnEventCreated (ipcEventStop->GetName ());
      }

      // Test if --inject PID is set where PID is a numeric value 
      // which stands for the remote process id.
      if (settings.inject.has_value () && settings.inject.value())
      {
         if (!Inject (settings.pid, GetLeakDetectFileName()))
         {
            qptr->OnInjectLibraryError (settings.pid);
            return false;
         }
         else
         {
            qptr->OnInjectLibrary (settings.pid);
         }
      }

      // The target process has loaded the detector.
      // From this point we are waiting for openeing the interrupt event
      // which happens during the first allocation / free.
      // After opening this event we are ready to communicate.
      ipcEventInterrupt->wait_until_opened ();
      qptr->OnEventOpened (ipcEventInterrupt->GetName ());

      ipcEventStartConfirm->wait_until_opened ();
      qptr->OnEventOpened (ipcEventStartConfirm->GetName ());
      
      ipcEventStopConfirm->wait_until_opened ();
      qptr->OnEventOpened (ipcEventStopConfirm->GetName ());
      
      // At this point we are ready to communicate with the target process.
      ipcEventStart->signal ();
      ipcEventStartConfirm->wait_for_signal ();
      qptr->OnProfilingStarted ();
      return true;
   }

   bool IsProcessAlive (DWORD pid)
   {
      DWORD aProcesses[1024], cbNeeded, cProcesses;
      memset (aProcesses, 0, sizeof (aProcesses));

      unsigned int i;
      if (!EnumProcesses (aProcesses, sizeof(aProcesses), &cbNeeded))
      {
         return false;
      }

      cProcesses = cbNeeded / sizeof(DWORD);
      for ( i = 0; i < cProcesses; i++ )
      {
         if (aProcesses[i] == pid)
            return true;
      }

      return false;
   }

   void mainloop (bool& bExitApplication)
   {
      bool remote_process_alive = true;

      const DWORD timeout = 250;

      for (;;)
      {
         // Wait for remote event..
         if (ipcEventInterrupt->wait_for_signal_timeout (timeout))
         {
            // Signal the worker..
            qptr->OnSignal (pid);

            // Resume remote execution..
            ipcEventInterruptConfirm->signal ();
         }
         else
         {
            qptr->OnTimeout (timeout);

            remote_process_alive = IsProcessAlive (pid);
            if (remote_process_alive)
               continue;
            else
               bExitApplication = true;
         }

         if (bExitApplication)
            break;
      }

      // Trigger the signal to stop profiling.
      if (remote_process_alive)
      {
         ipcEventStop->signal ();

         // It may happen that we have triggered the stop signal,
         // but there is still a pending allocation/free waiting for resuming
         // the remote process.
         while (ipcEventInterrupt->wait_for_signal_timeout (1000))
            ipcEventInterruptConfirm->signal ();

         // Wait to receive the confirm signal.
         ipcEventStopConfirm->wait_for_signal_timeout (10000);
      }

      qptr->OnProfilingStopped ();
   }

private:
   /// Returns the file name of the LeakDetect.dll.
   /// The file name is different depending on the current platform.
   std::string GetLeakDetectFileName ()
   {
   #if _WIN64
      const std::string& dll = "LeakDetect.X64.dll";
   #else
      const std::string& dll = "LeakDetect.X86.dll";
   #endif

      return dll;
   }
};

///
/// LeakClient
///
LeakClient::LeakClient ()
   : mPrivate (new Private(this))
{
}

LeakClient::~LeakClient ()
{
   delete mPrivate;
   mPrivate = nullptr;
}

bool LeakClient::bootstrap (const LEAKCLIENT_SETTINGS& settings)
{
   return mPrivate->bootstrap (settings);
}

void LeakClient::run_mainloop (bool& bExitApplication)
{
   mPrivate->mainloop (bExitApplication);
}

std::string LeakClient::GetLeakDetectFileName () const
{
   return mPrivate->GetLeakDetectFileName ();
}
