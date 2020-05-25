#include <sstream>
#include <fstream>
#include <algorithm>
#include <filesystem>
#include <iterator>
#include <iomanip>
#include <iostream>

#include "libLeak.h"
#include "LeakObject.h"
#include "LeakFileStream.h"

typedef std::vector<std::string> CSVRow;

// Borrowed from GenerateSQLite.cpp
std::filesystem::path GetDirectoryFromInputFile (const std::string& input);

class CSVFile
{
   std::fstream& fs;

public:
   CSVFile (std::fstream& file)
      : fs(file)
   {
   }

   ~CSVFile ()
   {
      if (fs.is_open ())
      {
         fs.flush ();
         fs.close ();
      }
   }

   inline CSVFile& this_ref () { return *this; }

   void WriteHeader (libLeak::LeakObjectType type)
   {
      switch (type)
      {
      case libLeak::LeakObjectType::Allocation:
         this_ref() << CSVRow { "Timestamp", "StacktraceID", "Pointer", "Size" };
         break;
      case libLeak::LeakObjectType::Deallocation:
         this_ref () << CSVRow { "Timestamp", "Pointer" };
         break;
      case libLeak::LeakObjectType::Stacktrace:
         this_ref () << CSVRow { "Timestamp", "StackTraceID", "Stacktrace" };
         break;
      default:
         break;
      }
   }

   std::string FormatTimestamp (uint64_t ts)
   {
      return std::to_string (ts);
   }

   std::string FormatPointer (intptr_t ptr)
   {
      std::stringstream ss;
      ss << "0x" << std::setfill ('0') << std::setw (sizeof (intptr_t) * 2) << std::hex << ptr;
      return ss.str ();
   }

   std::string FormatStacktrace (const std::vector<libLeak::SYMBOL_ENTRY>& stacktrace)
   {
      std::vector<std::string> lines;
      for (const auto& entry : stacktrace)
      {
         std::stringstream ss;
         ss << entry.name;
         if (!entry.file.empty ())
             ss << " @ " << entry.file << ":" << std::to_string (entry.line);

         lines.push_back (ss.str ());
      }

      return JoinString (lines, "\n");
   }

   std::string JoinString (const std::vector<std::string>& strings, const std::string& delimiter)
   {
      std::stringstream res;
      std::copy (strings.begin (), strings.end (), std::ostream_iterator<std::string> (res, delimiter.c_str()));
      return res.str ();
   }

   CSVFile& operator << (const libLeak::LeakObjectAllocation& object)
   {
      return this_ref () << CSVRow { FormatTimestamp(object.Timestamp), std::to_string(object.StacktraceId), FormatPointer(object.Pointer), std::to_string(object.ObjectSize) };
   }

   CSVFile& operator << (const libLeak::LeakObjectDeallocation& object)
   {
      return this_ref () << CSVRow { FormatTimestamp(object.Timestamp), FormatPointer(object.Pointer) };
   }

   CSVFile& operator << (const std::pair<const libLeak::LeakObjectStacktrace&, const std::vector<libLeak::SYMBOL_ENTRY>&> objectPair)
   {
      return this_ref () << CSVRow { FormatTimestamp (objectPair.first.Timestamp), std::to_string (objectPair.first.StacktraceId), FormatStacktrace (objectPair.second) };
   }

   CSVFile& operator << (const CSVRow& row)
   {
      if (!fs.is_open ())
         return *this;

      std::vector<std::string> quoted_strings;
      for (const auto& column : row)
      {
         std::stringstream ss;
         ss << std::quoted (column);
         quoted_strings.push_back (ss.str());
      }

      fs << JoinString (quoted_strings, ", ") << std::endl;
      return *this;
   }
};

void GenerateCSVFile (const std::string& input)
{
   std::filesystem::path base_dir = GetDirectoryFromInputFile (input);
   
   int index = 1;
   std::fstream fileAllocations (base_dir / ("allocations.csv"), std::fstream::out | std::fstream::trunc);
   if (!fileAllocations.is_open ())
   {
      std::cerr << "Could not open output file allocations.csv.." << std::endl;
      return;
   }

   std::fstream fileDeallocations (base_dir / ("deallocations.csv"), std::fstream::out | std::fstream::trunc);
   if (!fileDeallocations.is_open ())
   {
      std::cerr << "Could not open output file deallocations.csv.." << std::endl;
      return;
   }

   std::fstream fileStacktraces (base_dir / ("stacktrace.csv"), std::fstream::out | std::fstream::trunc);
   if (!fileStacktraces.is_open ())
   {
      std::cerr << "Could not open output file stacktrace.csv.." << std::endl;
      return;
   }

   FILE* fp = NULL;
   fopen_s (&fp, input.c_str (), "rb");
   if (fp == NULL)
   {
      std::cerr << "Could not open input file " << input << std::endl;
      return;
   }

   CSVFile csvAllocations (fileAllocations);
   csvAllocations.WriteHeader (libLeak::LeakObjectType::Allocation);

   CSVFile csvDeallocations (fileDeallocations);
   csvDeallocations.WriteHeader (libLeak::LeakObjectType::Deallocation);

   CSVFile csvStacktrace (fileStacktraces);
   csvStacktrace.WriteHeader (libLeak::LeakObjectType::Stacktrace);

   libLeak::LeakObject nextObject;
   libLeak::LeakFileStream stream (fp);
   
   libLeak::LeakObjectHeader header;
   if (!stream.ParseHeader (header) || libLeak::LeakObjectHeader::GetArchitecture() != header.Architecture)
   {
      std::cerr << "Could not parse input file. Invalid architecture." << std::endl;
      return;
   }

   while (stream.ParseObject (nextObject))
   {
      switch (nextObject.ObjectType)
      {
      
      // Serialize Allocations
      case (int)libLeak::LeakObjectType::Allocation:
      {
         libLeak::LeakObjectAllocation obj;
         if (stream.ParseAllocation (obj))
            csvAllocations << obj;
         break;
      }

      // Serialize Deallocations
      case (int)libLeak::LeakObjectType::Deallocation:
      {
         libLeak::LeakObjectDeallocation obj;
         if (stream.ParseDeallocation (obj))
            csvDeallocations << obj;
         break;
      }

      // Serialize Stacktrace
      case (int)libLeak::LeakObjectType::Stacktrace:
      {
         libLeak::LeakObjectStacktrace obj;
         std::vector<libLeak::SYMBOL_ENTRY> symbols;
         if (stream.ParseStacktrace (obj, symbols))
            csvStacktrace << std::pair<libLeak::LeakObjectStacktrace, std::vector<libLeak::SYMBOL_ENTRY>> (obj, symbols);
         break;
      }

      case (int)libLeak::LeakObjectType::Header:
      case (int)libLeak::LeakObjectType::Session:
      default:
         if (!stream.SkipObject (nextObject))
         {
            std::cerr << "Skipping object pointed to invalid position in file.\n";
            return;
         }
         break;
      }
   }
}