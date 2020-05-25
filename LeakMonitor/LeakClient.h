#pragma once

#include <Windows.h>

#include <string>
#include <optional>

///
/// LeakClient settings.
///
typedef struct LEAKCLIENT_SETTINGS_
{
   DWORD pid = 0;                            /// Remote Process ID
   std::optional<bool> inject;               /// Indicates whether the Leak.X86.dll / Leak.X64.dll
                                             /// should be injected to a remote process or not.
} LEAKCLIENT_SETTINGS;

///
/// LeakClient
///
/// The LeakClient class is responsible to connect to
/// a remote process and collects memory allocation, deallocation.
class LeakClient
{
public:
   /// Constructor
   LeakClient ();

   /// Destructor.
   virtual ~LeakClient ();

   /// Initializes the LeakClient.
   bool bootstrap (const LEAKCLIENT_SETTINGS& settings);

   /// Runs the Leak Client.
   /// The given reference is ready during the mainloop.
   /// Set the referenced bool to true once stopping the
   /// client is requested.
   void run_mainloop (bool& bExitApplication);

   /// Returns the Leak.dll name.
   std::string GetLeakDetectFileName () const;

protected:
   virtual void OnEventCreated (const std::string& eventName) { };
   virtual void OnEventCreateError (const std::string& eventName) { };

   virtual void OnInjectLibrary (DWORD processId) { };
   virtual void OnInjectLibraryError (DWORD processId) { };

   virtual void OnEventOpened (const std::string& eventName) { };

   virtual void OnProfilingStarted () { };
   virtual void OnProfilingStopped () { };

   virtual void OnSignal (DWORD pid) { };
   virtual void OnTimeout (DWORD timeoutMs) {};

private:
   class Private;
   Private* mPrivate;
};
