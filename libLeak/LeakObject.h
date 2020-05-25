#pragma once
#include <cstdint>

// Set explicit padding for the structures.
#pragma pack(push, 1)

namespace libLeak
{
   enum class LeakObjectType
   {
      Header      = 0,
      Session     = 1,
      Allocation  = 2,
      Deallocation = 3,
      Stacktrace  = 4
   };
   
   /// LeakObjectHeader
   /// File Header information.
   /// Indicates whether the given file is a LeakObject file or not.
   /// Architecture is set to 32 for a file that was written on a 32 bit platform,
   /// otherwise 64.
   struct LeakObjectHeader {
      uint32_t Magic;
      uint16_t Version;
      uint16_t Architecture;

      static uint16_t GetArchitecture ()
      {
      #ifdef _WIN64
         return (uint16_t)64;
      #else
         return (uint16_t)32;
      #endif
      }
   };

   /// LeakObject
   /// All objects in the raw file format inherit from LeakObject.
   struct LeakObject
   {
      uint8_t ObjectType;
      uint8_t Reserved1;
      size_t ObjectSize;
   };

   /// LeakObjectSession
   /// Meta information about the injected session.
   struct LeakObjectSession : public LeakObject {
      int32_t  ProcessId;
      uint64_t Timestamp;
   };

   /// LeakObjectAllocation
   /// Indicates a single allocation.
   struct LeakObjectAllocation : public LeakObject {
      uint32_t StacktraceId;
      uint64_t Timestamp;
      intptr_t Pointer;
      size_t   PointerSize;
   };

   /// LeakObjectDeallocation
   /// Indicates a single deallocation.
   struct LeakObjectDeallocation : public LeakObject {
      uint64_t Timestamp;
      intptr_t Pointer;
   };

   /// LeakObjectStacktrace
   /// Indicates a stacktrace.
   /// Note: This is a dynamic structure. The size depends on 'NumEntries'.
   /// All Entries are written after this structure.
   /// The layout of a single entry is stored in the following format.
   ///
   /// [size_t name_size  ]
   /// [char[name_size] name]
   /// [size_t file_line  ]
   /// [size_t file_size  ]
   /// [char[file_size] file]
   struct LeakObjectStacktrace : public LeakObject {
      uint64_t Timestamp;
      uint32_t StacktraceId;
      size_t   NumEntries;
      
      // [Entries]
   };
}

#pragma pack(pop, 1) // explicit padding
