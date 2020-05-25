#include "LeakFileStreamSerializer.h"

#include "LeakObject.h"

namespace libLeak
{
   void LeakFileStreamSerializer::SerializeHeader (std::vector<uint8_t>& bytes)
   {
      bytes.resize (sizeof (LeakObjectHeader));
      LeakObjectHeader* item = (LeakObjectHeader*)bytes.data ();
      item->Architecture = LeakObjectHeader::GetArchitecture ();
      item->Version = 1;
      item->Magic = 'KAEL';
   }

   void LeakFileStreamSerializer::SerializeSession (
      std::vector<uint8_t>& bytes, 
      DWORD pid, 
      uint64_t ts)
   {
      bytes.resize (sizeof (LeakObjectSession));
      LeakObjectSession* item = (LeakObjectSession*)bytes.data ();
      item->ObjectSize = bytes.size ();
      item->ObjectType = (uint8_t)LeakObjectType::Session;
      item->ProcessId = pid;
      item->Timestamp = ts;
   }

   void LeakFileStreamSerializer::SerializeAllocation (
      std::vector<uint8_t>& bytes, 
      libLeak::PALLOCATION_EVENT allocation, 
      uint32_t stacktrace_id)
   {
      bytes.resize (sizeof (LeakObjectAllocation));
      LeakObjectAllocation* item = (LeakObjectAllocation*)bytes.data ();
      item->ObjectSize = bytes.size ();
      item->ObjectType = (uint8_t)LeakObjectType::Allocation;
      item->Pointer = allocation->Pointer;
      item->PointerSize = allocation->Size;
      item->Timestamp = allocation->TimestampEpochSeconds;
      item->StacktraceId = stacktrace_id;
   }

   void LeakFileStreamSerializer::SerializeDeallocation (
      std::vector<uint8_t>& bytes, 
      libLeak::PDELLOCATION_EVENT deallocation)
   {
      bytes.resize (sizeof (LeakObjectDeallocation));
      LeakObjectDeallocation* item = (LeakObjectDeallocation*)bytes.data ();
      item->ObjectSize = bytes.size ();
      item->ObjectType = (uint8_t)LeakObjectType::Deallocation;
      item->Pointer = deallocation->Pointer;
      item->Timestamp = deallocation->TimestampEpochSeconds;
   }

   void LeakFileStreamSerializer::SerializeStacktrace (
      std::vector<uint8_t>& bytes, 
      uint32_t stacktrace_id, 
      const std::vector<libLeak::SYMBOL_ENTRY>& symbols,
      uint64_t ts)
   {
      bytes.resize (sizeof (LeakObjectStacktrace));
      LeakObjectStacktrace* item = (LeakObjectStacktrace*)bytes.data ();
      item->ObjectSize = bytes.size();
      item->ObjectType = (uint8_t)LeakObjectType::Stacktrace;
      item->StacktraceId = stacktrace_id;
      item->NumEntries = symbols.size ();
      item->Timestamp = ts;

      // Enumerate all symbols
      for (const auto& symbol : symbols)
      {
         // Store symbol information to local variables..
         const auto& name = symbol.name;
         const size_t name_size = symbol.name.size ();

         const auto& file = symbol.file;
         const size_t file_size = symbol.file.size ();
         const size_t file_line = symbol.line;

         // store end of byte offset
         size_t previousSize = bytes.size ();

         // increase byte buffer to store symbol name
         bytes.resize (bytes.size () + sizeof (size_t) + name_size);
         char* offset = (char*)(bytes.data () + previousSize);
         memcpy (offset, &name_size, sizeof (size_t));
         if (name_size) memcpy (offset + sizeof (size_t), name.c_str (), name_size);

         // store end of byte offset
         previousSize = bytes.size ();

         // increase byte buffer to store symbol file information
         bytes.resize (bytes.size () + (sizeof (size_t) * 2) + file_size);
         offset = (char*)(bytes.data () + previousSize);
      
         memcpy (offset, &file_line, sizeof (size_t));
         memcpy (offset + sizeof(size_t), &file_size, sizeof (size_t));
         if (file_size) memcpy (offset + (sizeof (size_t) * 2), file.c_str (), file_size);

         // update item size
         item = (LeakObjectStacktrace*)bytes.data ();
         item->ObjectSize = bytes.size ();
      }
   }
}