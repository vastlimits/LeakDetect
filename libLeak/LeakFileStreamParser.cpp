#include "LeakFileStreamParser.h"

namespace libLeak
{
   bool LeakFileStreamParser::ParseObject (FILE* stream, LeakObject& object)
   {
      if (stream == NULL)
         return false;

      auto previous = ftell (stream);
      bool success = fread (&object, sizeof (LeakObject), 1, stream) == 1;
      if (success)
      {
         previous = ftell (stream);
         fseek (stream, - (long)sizeof (LeakObject), SEEK_CUR);
         auto now = ftell (stream);
         return previous > now;
      }

      return false;
   }

   bool LeakFileStreamParser::SkipObject (FILE* stream, const LeakObject& object)
   {
      auto now = ftell (stream);
      if (object.ObjectSize > LONG_MAX)
         return false;

      fseek (stream, (long)object.ObjectSize, SEEK_CUR);
      return ftell (stream) == now + object.ObjectSize;
   }
   
   bool LeakFileStreamParser::ParseHeader (FILE* stream, LeakObjectHeader& header)
   {
      return ftell(stream) == 0 && fread (&header, sizeof (LeakObjectHeader), 1, stream) == 1;
   }

   bool LeakFileStreamParser::ParseSession (FILE* stream, LeakObjectSession& session)
   {
      return fread (&session, sizeof (LeakObjectSession), 1, stream) == 1
         && session.ObjectType == (int)LeakObjectType::Session;
   }

   bool LeakFileStreamParser::ParseAllocation (FILE* stream, LeakObjectAllocation& allocation)
   {
      return fread (&allocation, sizeof (LeakObjectAllocation), 1, stream) == 1
         && allocation.ObjectType == (int)LeakObjectType::Allocation;
   }
   
   bool LeakFileStreamParser::ParseDeallocation (FILE* stream, LeakObjectDeallocation& deallocation)
   {
      return fread (&deallocation, sizeof (LeakObjectDeallocation), 1, stream) == 1
         && deallocation.ObjectType == (int)LeakObjectType::Deallocation;
   }

   bool LeakFileStreamParser::ParseStacktrace (FILE* stream, LeakObjectStacktrace& stacktrace, std::vector<libLeak::SYMBOL_ENTRY>& symbols)
   {
      if (fread (&stacktrace, sizeof (LeakObjectStacktrace), 1, stream) == 1)
      {
         // Parsed the stacktrace header. Parse the entries now.
         for (uint32_t i = 0; i < stacktrace.NumEntries; i++)
         {
            // The layout of a single entry is stored in the following format.
            // [size_t name_size  ]
            // [char[name_size] name]
            // [size_t file_line  ]
            // [size_t file_size  ]
            // [char[file_size] file]
            
            std::string name;
            uint32_t name_size = 0;
            if (fread (&name_size, sizeof (size_t), 1, stream) == 1)
            {
               // Symbol name is not empty.
               name.resize (name_size);
               if (fread (name.data (), name_size, 1, stream) != 1)
               {
                  name.clear ();
                  name.shrink_to_fit ();
               }
            }

            size_t file_line;
            fread(&file_line, sizeof(size_t), 1, stream);

            std::string file;
            size_t file_size;
            if (fread (&file_size, sizeof (size_t), 1, stream) == 1)
            {
               // Symbol name is not empty.
               file.resize (file_size);
               if (fread (file.data (), file_size, 1, stream) != 1)
               {
                  file.clear ();
                  file.shrink_to_fit ();
               }
            }

            symbols.push_back ({ name, file, (DWORD)file_line });
         }

         return true;
      }

      return false;
   }

}