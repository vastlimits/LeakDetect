#pragma once

#include "libLeak.h"
#include "LeakObject.h"

namespace libLeak
{
   ///
   /// The LeakFileStream class handles serialization of leak
   /// events such as allocations, deallocations.
   ///
   class LeakFileStream
   {
      FILE* file;

   public:
      /// Constructs a new LeakFileStream. The ownership of FILE* is 
      /// transferred to this instance.
      LeakFileStream (FILE* fp);

      /// Destructor. Closes the opened FILE*.
      virtual ~LeakFileStream ();

      LeakFileStream (const LeakFileStream&) = delete;
      LeakFileStream (LeakFileStream&&) = delete;
      LeakFileStream& operator = (const LeakFileStream&) = delete;

      /// Serializes the native binary header
      void WriteHeader ();

      /// Serializes session information (process identifier, epoch timestamp)
      void WriteSession (DWORD pid, uint64_t ts);

      /// Serializes a stacktrace
      void WriteStacktrace (uint32_t id, const std::vector<libLeak::SYMBOL_ENTRY>& symbols, uint64_t ts);
      
      /// Serializes an allocation
      void WriteAllocation (uint32_t id, libLeak::PALLOCATION_EVENT allocation);

      /// Serializes a deallocation
      void WriteDeallocation (libLeak::PDELLOCATION_EVENT deallocation);

      /// Parses the next object in the native binary stream.
      /// Returns true on success, otherwise false.
      bool ParseObject  (LeakObject& object);

      /// Skips the next object in the native binary stream.
      /// Returns true on success, otherwise false.
      bool SkipObject (const LeakObject& object);

      /// Parses the header object.
      /// Returns true on success, otherwise false.
      bool ParseHeader  (LeakObjectHeader& header);
      
      /// Parses the session object.
      /// Returns true on success, otherwise false.
      bool ParseSession (LeakObjectSession& session);
      
      /// Parses an allocation object.
      /// Returns true on success, otherwise false.
      bool ParseAllocation (LeakObjectAllocation& allocation);
      
      /// Parses a deallocation object.
      /// Returns true on success, otherwise false.
      bool ParseDeallocation (LeakObjectDeallocation& deallocation);

      /// Parses a stacktrace object.
      /// Returns true on success, otherwise false.
      bool ParseStacktrace (LeakObjectStacktrace& stacktrace, std::vector<libLeak::SYMBOL_ENTRY>& symbols);

   private:
      void Write (const std::vector<uint8_t>& bytes);
      void Read (std::vector<uint8_t>& bytes);
   };
}