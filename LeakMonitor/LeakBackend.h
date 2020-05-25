#pragma once
#include "libLeak.h"

///
/// Abstract LeakBackend
/// Implement this class to handle allocation and deallocation events.
///
class LeakBackend
{
public:
   LeakBackend () = default;
   virtual ~LeakBackend () = default;

   /// Called as soon as the program is initialized.
   virtual void initialize (DWORD pid) = 0;

   /// Called synchronously for each allocation event.
   /// Make sure to not do any heavy operation in this routine.
   virtual void push (_In_ libLeak::PALLOCATION_EVENT event) = 0;

   /// Called synchronously for each deallocation event.
   /// Make sure to not do any heavy operation in this routine.
   virtual void push (_In_ libLeak::PDELLOCATION_EVENT event) = 0;

   /// Called synchronously for each signal timeout.
   /// Happens when the remote process is IDLE and is not doing
   /// any allocation / deallocation.
   virtual void signal_timeout () = 0;

   /// Updates the current remote process handle to the symbol backend engine.
   virtual void SetRemoteProcessHandle (HANDLE handle) = 0;
};
