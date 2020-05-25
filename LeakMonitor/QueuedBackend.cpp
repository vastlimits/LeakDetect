#include "QueuedBackend.h"

// Forward to Stacktrace.cpp
HRESULT CaptureStackTraceWithSymbols (
   __in HANDLE RemoteProcess,
   __in CONST libLeak::PSTACKTRACE StackTrace,
   std::vector<libLeak::SYMBOL_ENTRY>& SymbolStackTrace);

DWORD WINAPI QueuedBackendThread (LPVOID lpParameter)
{
   return static_cast<QueuedBackend*>(lpParameter)->QueuedBackendThread ();
}

QueuedBackend::QueuedBackend ()
{
   InitializeCriticalSection (&csThreading);
}

QueuedBackend::~QueuedBackend ()
{
   DeleteCriticalSection (&csThreading);
}

void QueuedBackend::join ()
{
   if (hThread == NULL)
      return;

   // Interrupt the thread.
   if (hThreadInterruptEvent)
   {
      // Synchronize all pending events to the thread.
      while (synchronize_queue (true))
      {
         // Notify the thread.
         interrupt_thread ();
      }

      // Now make sure the thread picked up all elements.
      while (true)
      {
         EnterCriticalSection (&csThreading);
         bool empty = event_queue_thread.size() == 0;
         LeaveCriticalSection (&csThreading);

         if (empty) 
            break;
         else
         {
            Sleep (100);
            continue;
         }
      }

      // Now; all elements were picked up by the thread.
      // Signal the thread to finish work and exit.
      EnterCriticalSection (&csThreading);
      bThreadExitRequested = true;
      LeaveCriticalSection (&csThreading);

      // Perform interrupt.
      SetEvent (hThreadInterruptEvent);

      // Wait for the thread to exit.
      // That should be the case the thread is signalled. An internal error most likely
      // means that the thread is exited already.
      WaitForSingleObject (hThread, INFINITE);

      // Close interrupt event handle.
      CloseHandle (hThreadInterruptEvent);
      hThreadInterruptEvent = NULL;
   }
   else
   {
      // For some reason our interrupt event is corrupt.
      // Make sure to terminate the thread by now.
      TerminateThread (hThread, 0);
   }
      
   // Close thread handle.
   CloseHandle (hThread);
   hThread = NULL;
}

void QueuedBackend::initialize (DWORD pid)
{
   last_queue_push = std::chrono::steady_clock::now ();

   // We must confirm that the thread is running and available
   // when leaving this function.
   while (hThreadStartedEvent == NULL || hThreadInterruptEvent == NULL)
   {
      if (hThreadStartedEvent == NULL)
      {
         hThreadStartedEvent = CreateEvent (NULL, FALSE, FALSE, NULL);
         if (hThreadStartedEvent == NULL) 
            Sleep (100);
      }
      
      if (hThreadInterruptEvent == NULL)
      {
         hThreadInterruptEvent = CreateEvent (NULL, FALSE, FALSE, NULL);
         if (hThreadInterruptEvent == NULL) 
            Sleep (100);
      }
   }

   // Thread creation must succeed.
   while (hThread == NULL)
   {
      hThread = CreateThread (NULL, 0, ::QueuedBackendThread, (LPVOID)this, 0, NULL);
      if (hThread == NULL) Sleep (100);
   }

   // Wait for the thread to signal us.
   while (WAIT_OBJECT_0 != WaitForSingleObject (hThreadStartedEvent, INFINITE))
      Sleep (100);

   // Close the handle.
   CloseHandle (hThreadStartedEvent);
   hThreadStartedEvent = NULL;

   OnInitialized (pid);
}

/// Called synchronously for each allocation event.
/// Make sure to not do any heavy operation in this routine.
void QueuedBackend::push (_In_ libLeak::PALLOCATION_EVENT event)
{
   event_queue.push_back ({event, NULL});
   update_queue ();
}

/// Called synchronously for each deallocation event.
/// Make sure to not do any heavy operation in this routine.
void QueuedBackend::push (_In_ libLeak::PDELLOCATION_EVENT event)
{
   event_queue.push_back ({NULL, event});
   update_queue ();
}

/// Called synchronously for each timeout event.
/// The remote process is in IDLE state at this point.
void QueuedBackend::signal_timeout ()
{
   update_queue (true);
}

void QueuedBackend::SetRemoteProcessHandle (HANDLE handle) 
{
   hRemoteProcess = handle;
}


DWORD QueuedBackend::QueuedBackendThread ()
{
   // Notify the main thread that we are ready.
   SetEvent (hThreadStartedEvent);

   for (;;)
   {
      // Wait for interrupt.
      if (WaitForSingleObject (hThreadInterruptEvent, INFINITE) != WAIT_OBJECT_0)
      {
         // If waiting infinite is not possible, break out of this thread function
         // to avoid processing infinite for nothing.
         break;
      }

      std::vector<LEAKEVENT> events;
      EnterCriticalSection (&csThreading);
      {
         event_queue_thread.swap (events);
      }
      LeaveCriticalSection (&csThreading);

      // Process the events..
      for (auto& event : events)
         OnProcessEventInternal (event);

      if (bThreadExitRequested &&
         event_queue_thread.size () == 0 &&
         event_queue.size () == 0)
      {
         break;
      }
   }
   return 0;
}

void QueuedBackend::OnProcessEventInternal (LEAKEVENT& event)
{
   // Grab symbolic information for allocations..
   if (event.allocation)
   {
      CaptureStackTraceWithSymbols (
         hRemoteProcess, 
         &event.allocation->Stacktrace, 
         event.symbols);
   }
   OnProcessEvent (event);
}

void QueuedBackend::update_queue (bool force)
{
   if (synchronize_queue (force))
   {
      interrupt_thread ();
   }
}

bool QueuedBackend::synchronize_queue (bool force)
{
   if (event_queue.size () == 0)
      return false;

   auto now = std::chrono::steady_clock::now ();
   if (force || std::chrono::duration_cast<std::chrono::milliseconds> (now - last_queue_push).count () >= 5000)
   {
      EnterCriticalSection (&csThreading);

      for (const auto& entry : event_queue)
         event_queue_thread.push_back (entry);

      event_queue.clear ();
      event_queue.shrink_to_fit ();
      last_queue_push = std::chrono::steady_clock::now ();

      LeaveCriticalSection (&csThreading);
      return true;
   }

   return false;
}

void QueuedBackend::interrupt_thread ()
{
   SetEvent (hThreadInterruptEvent);
}
