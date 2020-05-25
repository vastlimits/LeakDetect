#include "libLeak.h"

#include <locale>
#include <string>
#include <sstream>

///
/// Template Identifiers where $dynamic is replaces with the target
/// process PID.
///
const char* libLeak::VL_MEMORY_EVENT_INTERRUPT = "Global\\vl.leak.$dynamic.interrupt";
const char* libLeak::VL_MEMORY_EVENT_REMOTE_START = "Global\\vl.leak.$dynamic.start";
const char* libLeak::VL_MEMORY_EVENT_START_CONFIRM = "Global\\vl.leak.$dynamic.start.confirm";
const char* libLeak::VL_MEMORY_EVENT_REMOTE_STOP = "Global\\vl.leak.$dynamic.stop";
const char* libLeak::VL_MEMORY_EVENT_STOP_CONFIRM = "Global\\vl.leak.$dynamic.stop.confirm";
const char* libLeak::VL_MEMORY_EVENT_REMOTE_INTERRUPT_CONTINUE = "Global\\vl.leak.$dynamic.interrupt.continue";

/// Utility: Replace substring.
void replace(std::string& str, const std::string& from, const std::string& to) 
{
   size_t start_pos = str.find(from);
   if (start_pos == std::string::npos)
      return;
    
   str.replace (start_pos, from.length (), to);
}

/// Replaces the variables in a template event name.
std::string libLeak::ReplaceEventName (const char* eventName, DWORD processId)
{
   std::string result (eventName, strlen (eventName));
   replace (result, "$dynamic", std::to_string (processId));
   return result;
}

/// Default by http://isthe.com/chongo/tech/comp/fnv/
const uint32_t Prime = 0x01000193;
const uint32_t Seed  = 0x811C9DC5;

/// Hash a single byte..
inline uint32_t fnv1a(unsigned char byte, uint32_t hash = Seed)
{
  return (byte ^ hash) * Prime;
}

/// Hash a block of memory..
uint32_t fnv1a(const void* data, size_t numBytes, uint32_t hash = Seed)
{
   const unsigned char* ptr = (const unsigned char*)data;
   while (numBytes--)
   {
      hash = fnv1a (*ptr++, hash);
   }
   return hash;
}

/// Hash a std::string
uint32_t fnv1a(const std::string& text, uint32_t hash = Seed)
{
   return fnv1a (text.c_str(), text.length(), hash);
}

///
/// Generates a "unique" identifier by the given symbols.
/// We need this to write down a stacktrace once and have a reference to to the stacktrace
/// for each allocation.
///
uint32_t libLeak::CreateUniqueId (
   const std::vector<libLeak::SYMBOL_ENTRY>& symbols)
{
   std::stringstream ss;
   for (const auto& entry : symbols)
   {
      if (entry.name.size () == 0)
         continue;

      ss << "[" << entry.name << "]";
   }

   return fnv1a (ss.str ());
}
