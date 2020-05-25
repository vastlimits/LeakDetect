#pragma once

#include <Windows.h>

#include <string>
#include <vector>

namespace libLeak
{
   // Instrumentation Type
   enum class InstrumentType
   {
      Invalid        = 0,
      Allocation     = 1,
      Deallocation    = 2,
   };

   //
   // Shared Metadata structures
   // that are part of the IPC between the instrumented process
   // and the monitoring process.
   //

   typedef struct ANALYZER_METADATA_ {
      CONTEXT Context;                       // CPU Context
      DWORD Type;                            // Type
      SIZE_T Size;                           // Allocated Size [if Type is Allocate]
      intptr_t Pointer;                      // Allocated Pointer
   } ANALYZER_METADATA, *PANALYZER_METADATA;

   const int MaximumStackTraceFrames = 24;
   typedef struct _STACKTRACE 
   {
      UINT FrameCount;
      intptr_t Frames[MaximumStackTraceFrames];
   } STACKTRACE, * PSTACKTRACE;

   typedef struct ALLOCATION_EVENT_ {
      SIZE_T Size;
      intptr_t Pointer;
      uint64_t TimestampEpochSeconds;
      libLeak::STACKTRACE Stacktrace;
   } ALLOCATION_EVENT, *PALLOCATION_EVENT;

   typedef struct DELLOCATION_EVENT_ {
      intptr_t Pointer;
      uint64_t TimestampEpochSeconds;
   } DELLOCATION_EVENT, *PDELLOCATION_EVENT;

   typedef struct SYMBOL_ENTRY_ {
      std::string name;
      std::string file;
      DWORD line;
   } SYMBOL_ENTRY, *PSYMBOL_ENTRY;

   extern const char* VL_MEMORY_EVENT_INTERRUPT;
   extern const char* VL_MEMORY_EVENT_REMOTE_START;
   extern const char* VL_MEMORY_EVENT_START_CONFIRM;
   extern const char* VL_MEMORY_EVENT_REMOTE_STOP;
   extern const char* VL_MEMORY_EVENT_STOP_CONFIRM;
   extern const char* VL_MEMORY_EVENT_REMOTE_INTERRUPT_CONTINUE;

   /// Replaces a template-event name to a pid-specific-event name.
   std::string ReplaceEventName (const char* eventName, DWORD processId);

   /// Returns a hash from given symbol entries.
   uint32_t CreateUniqueId (const std::vector<libLeak::SYMBOL_ENTRY>& symbols);
}