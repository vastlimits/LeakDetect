#include "LeakFileStream.h"

#include "LeakObject.h"
#include "LeakFileStreamSerializer.h"
#include "LeakFileStreamParser.h"

namespace libLeak
{
   LeakFileStream::LeakFileStream (FILE* fp)
      : file (fp)
   {
   }

   LeakFileStream::~LeakFileStream ()
   {
      if (file)
      {
         fclose (file);
      }
   }

   void LeakFileStream::WriteHeader ()
   {
      std::vector<uint8_t> bytes;
      LeakFileStreamSerializer::SerializeHeader (bytes);
      Write (bytes);
   }

   void LeakFileStream::WriteSession (DWORD pid, uint64_t ts)
   {
      std::vector<uint8_t> bytes;
      LeakFileStreamSerializer::SerializeSession (bytes, pid, ts);
      Write (bytes);
   }

   void LeakFileStream::WriteStacktrace (uint32_t id, const std::vector<libLeak::SYMBOL_ENTRY>& symbols, uint64_t ts)
   {
      std::vector<uint8_t> bytes;
      LeakFileStreamSerializer::SerializeStacktrace (bytes, id, symbols, ts);
      Write (bytes);
   }

   void LeakFileStream::WriteAllocation (uint32_t id, libLeak::PALLOCATION_EVENT allocation)
   {
      std::vector<uint8_t> bytes;
      LeakFileStreamSerializer::SerializeAllocation (bytes, allocation, id);
      Write (bytes);
   }

   void LeakFileStream::WriteDeallocation (libLeak::PDELLOCATION_EVENT deallocation)
   {
      std::vector<uint8_t> bytes;
      LeakFileStreamSerializer::SerializeDeallocation (bytes, deallocation);
      Write (bytes);
   }

   bool LeakFileStream::ParseObject (LeakObject& object)
   {
      return LeakFileStreamParser::ParseObject (file, object);
   }

   bool LeakFileStream::SkipObject (const LeakObject& object)
   {
      return LeakFileStreamParser::SkipObject (file, object);
   }

   bool LeakFileStream::ParseHeader (LeakObjectHeader& header)
   {
      return LeakFileStreamParser::ParseHeader (file, header);
   }

   bool LeakFileStream::ParseSession (LeakObjectSession& session)
   {
      return LeakFileStreamParser::ParseSession (file, session);
   }

   bool LeakFileStream::ParseAllocation (LeakObjectAllocation& allocation)
   {
      return LeakFileStreamParser::ParseAllocation (file, allocation);
   }

   bool LeakFileStream::ParseDeallocation (LeakObjectDeallocation& deallocation)
   {
      return LeakFileStreamParser::ParseDeallocation (file, deallocation);
   }

   bool LeakFileStream::ParseStacktrace (LeakObjectStacktrace& stacktrace, std::vector<libLeak::SYMBOL_ENTRY>& symbols)
   {
      return LeakFileStreamParser::ParseStacktrace (file, stacktrace, symbols);
   }

   void LeakFileStream::Write (const std::vector<uint8_t>& bytes)
   {
      if (bytes.size ())
      {
         fwrite ((const void*)bytes.data(), bytes.size(), 1, file);
      }
   }

   void LeakFileStream::Read (std::vector<uint8_t>& bytes)
   {
      const size_t size_hdr = sizeof (LeakObject);

      // The buffer must be at least have enough memory to store the header.
      if (bytes.size () < size_hdr)
         bytes.resize (size_hdr);

      // Read the header.
      if (size_hdr == fread (bytes.data (), size_hdr, 1, file))
      {
         // Grab the total object size.
         const size_t object_size = ((LeakObject*)bytes.data ())->ObjectSize;

         // Make sure this is valid.
         if (object_size > size_hdr)
         {
            // Resize the buffer to the actual object size.
            bytes.resize (object_size);

            // Get the remaining size and read the remaining bytes.
            const size_t remaining_read_size = object_size - size_hdr;
            if (remaining_read_size == fread (bytes.data () + size_hdr, remaining_read_size, 1, file))
            {
               return;
            }
         }
      }

      // Something went wrong. Revert the buffer; so the caller
      // can simply check if the bytes are empty or not.
      bytes.clear ();
      bytes.shrink_to_fit ();
   }
}
