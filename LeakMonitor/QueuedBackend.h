#pragma once
#include "libLeak.h"
#include "LeakBackend.h"

#include <chrono>
#include <vector>

typedef struct LEAKEVENT_ {
   libLeak::PALLOCATION_EVENT allocation;
   libLeak::PDELLOCATION_EVENT deallocation;
   std::vector<libLeak::SYMBOL_ENTRY> symbols;
} LEAKEVENT, *PLEAKEVENT;

class QueuedBackend : public LeakBackend
{
   HANDLE hRemoteProcess = NULL;
   HANDLE hThread = NULL;
   HANDLE hThreadStartedEvent = NULL;
   HANDLE hThreadInterruptEvent = NULL;
   CRITICAL_SECTION csThreading;
   bool bThreadExitRequested = false;
   std::vector<LEAKEVENT> event_queue;
   std::vector<LEAKEVENT> event_queue_thread;
   std::chrono::steady_clock::time_point last_queue_push;

public:
   QueuedBackend ();
   virtual ~QueuedBackend () override;

   /// Must be called before deleting the backend.
   void join ();

   /// Called as soon as the program is initialized.
   virtual void initialize (DWORD pid) override;

   /// Called synchronously for each allocation event.
   /// Make sure to not do any heavy operation in this routine.
   virtual void push (_In_ libLeak::PALLOCATION_EVENT event) override;

   /// Called synchronously for each deallocation event.
   /// Make sure to not do any heavy operation in this routine.
   virtual void push (_In_ libLeak::PDELLOCATION_EVENT event) override;

   /// Called synchronously for each timeout event.
   /// The remote process is in IDLE state at this point.
   virtual void signal_timeout () override;

   /// Updates the current remote process handle to the symbol backend engine.
   virtual void SetRemoteProcessHandle (HANDLE handle) override;

   /// Threaded queue.
   DWORD QueuedBackendThread ();

protected:
   virtual void OnInitialized (DWORD pid) = 0;
   virtual void OnProcessEvent (const LEAKEVENT& event) = 0;

private:
   void OnProcessEventInternal (LEAKEVENT& event);

private:
   void update_queue (bool force = false);
   bool synchronize_queue (bool force = false);
   void interrupt_thread ();
};
