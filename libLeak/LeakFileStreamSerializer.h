#pragma once

#include "libLeak.h"

namespace libLeak
{
   class LeakFileStreamSerializer
   {
      LeakFileStreamSerializer () = delete;
      ~LeakFileStreamSerializer () = delete;
      LeakFileStreamSerializer (const LeakFileStreamSerializer&) = delete;
      LeakFileStreamSerializer (LeakFileStreamSerializer&&) = delete;
      LeakFileStreamSerializer& operator= (const LeakFileStreamSerializer&) = delete;

   public:
      /// Serializes the native binary header
      static void SerializeHeader (std::vector<uint8_t>& bytes);
      
      /// Serializes session information (process identifier, epoch timestamp)
      static void SerializeSession (std::vector<uint8_t>& bytes, DWORD pid, uint64_t ts);
      
      /// Serializes an allocation
      static void SerializeAllocation (std::vector<uint8_t>& bytes, libLeak::PALLOCATION_EVENT allocation, uint32_t stacktrace_id);
      
      /// Serializes a deallocation
      static void SerializeDeallocation (std::vector<uint8_t>& bytes, libLeak::PDELLOCATION_EVENT deallocation);
      
      /// Serializes a stacktrace
      static void SerializeStacktrace (std::vector<uint8_t>& bytes, uint32_t stacktrace_id, const std::vector<libLeak::SYMBOL_ENTRY>& symbols, uint64_t ts);
   };
}
