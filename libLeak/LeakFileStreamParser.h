#pragma once

#include "libLeak.h"
#include "LeakObject.h"

namespace libLeak
{
   /// Static helper class to encapusalte the actual methods
   /// to parse objects from the native binary file.
   class LeakFileStreamParser
   {
      LeakFileStreamParser () = delete;
      ~LeakFileStreamParser () = delete;
      LeakFileStreamParser (const LeakFileStreamParser&) = delete;
      LeakFileStreamParser (LeakFileStreamParser&&) = delete;
      LeakFileStreamParser& operator= (const LeakFileStreamParser&) = delete;

   public:
      /// Parses the next object in the native binary stream.
      /// Returns true on success, otherwise false.
      static bool ParseObject  (FILE* stream, LeakObject& object);

      /// Skips the next object in the native binary stream.
      /// Returns true on success, otherwise false.
      static bool SkipObject (FILE* stream, const LeakObject& object);

      /// Parses the header object.
      /// Returns true on success, otherwise false.
      static bool ParseHeader  (FILE* stream, LeakObjectHeader& header);

      /// Parses the session object.
      /// Returns true on success, otherwise false.
      static bool ParseSession (FILE* stream, LeakObjectSession& session);

      /// Parses an allocation object.
      /// Returns true on success, otherwise false.
      static bool ParseAllocation (FILE* stream, LeakObjectAllocation& allocation);

      /// Parses a deallocation object.
      /// Returns true on success, otherwise false.
      static bool ParseDeallocation (FILE* stream, LeakObjectDeallocation& deallocation);

      /// Parses a stacktrace object.
      /// Returns true on success, otherwise false.
      static bool ParseStacktrace (FILE* stream, LeakObjectStacktrace& stacktrace, std::vector<libLeak::SYMBOL_ENTRY>& symbols);
   };
}
