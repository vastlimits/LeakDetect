#include "libLeak.h"

#include <vector>

#include <DbgHelp.h>

#pragma comment(lib, "DbgHelp.lib")

/// Utility: Get a symbol from a given address..
bool GetSymbolFromFrameAddress (HANDLE hProcess, PSYMBOL_INFO symbol, intptr_t address)
{
   static thread_local DWORD64 dwDisplacement64{ 0 };

   memset (symbol, 0, sizeof (SYMBOL_INFO));
   symbol->SizeOfStruct = sizeof (SYMBOL_INFO);
   symbol->MaxNameLen = MAX_SYM_NAME;
   
   return SymFromAddr (hProcess, address, &dwDisplacement64, symbol) == TRUE;
}

/// Utility: Get source code file and line number from a given address..
std::pair<std::string, DWORD> GetSymbolSourceFile (HANDLE hProcess, intptr_t address)
{
   static thread_local IMAGEHLP_LINE line{ 0 };
   static thread_local DWORD dwDisplacement{ 0 };

   memset (&line, 0, sizeof (IMAGEHLP_LINE));
   line.SizeOfStruct = sizeof (IMAGEHLP_LINE);

   BOOL has_symbol_file = SymGetLineFromAddr (hProcess, address, &dwDisplacement, &line);
   if (has_symbol_file)
   {
      return std::pair<std::string, DWORD>{line.FileName, line.LineNumber};
   }

   return {};
}

HRESULT CaptureStackTrace (
   __in CONST PCONTEXT Context,
   __in HANDLE RemoteProcess,
   __in libLeak::PSTACKTRACE StackTrace)
{
   DWORD MachineType;
   STACKFRAME StackFrame;

   if (Context == NULL)
      return S_FALSE;

   //
   // Set up stack frame.
   //
   ZeroMemory (&StackFrame, sizeof (STACKFRAME));
#ifdef _WIN64
   MachineType = IMAGE_FILE_MACHINE_AMD64;
   StackFrame.AddrPC.Offset = Context->Rip;
   StackFrame.AddrPC.Mode = AddrModeFlat;
   StackFrame.AddrFrame.Offset = Context->Rsp;
   StackFrame.AddrFrame.Mode = AddrModeFlat;
   StackFrame.AddrStack.Offset = Context->Rsp;
   StackFrame.AddrStack.Mode = AddrModeFlat;
#else
   MachineType = IMAGE_FILE_MACHINE_I386;
   StackFrame.AddrPC.Offset = Context->Eip;
   StackFrame.AddrPC.Mode = AddrModeFlat;
   StackFrame.AddrFrame.Offset = Context->Esp;
   StackFrame.AddrFrame.Mode = AddrModeFlat;
   StackFrame.AddrStack.Offset = Context->Esp;
   StackFrame.AddrStack.Mode = AddrModeFlat;
#endif

   StackTrace->FrameCount = 0;

   while (StackTrace->FrameCount < libLeak::MaximumStackTraceFrames)
   {
      if (!StackWalk (
         MachineType,
         RemoteProcess,
         (HANDLE)0xDEADBEEFC0DECAFE,
         &StackFrame,
         Context,
         NULL,
         SymFunctionTableAccess,
         SymGetModuleBase,
         NULL))
      {
         //
         // Maybe it failed, maybe we have finished walking the stack.
         //
         break;
      }

      if (StackFrame.AddrPC.Offset != 0)
      {
         //
         // Valid frame.
         //
         StackTrace->Frames[StackTrace->FrameCount++] = StackFrame.AddrPC.Offset;
      }
      else
      {
         //
         // Base reached.
         //
         break;
      }
   }

   return S_OK;
}

HRESULT CaptureStackTraceWithSymbols (
   __in HANDLE RemoteProcess,
   __in CONST libLeak::PSTACKTRACE StackTrace,
   std::vector<libLeak::SYMBOL_ENTRY>& SymbolStackTrace)
{
   static bool initialized = false;
   static bool initialized_success = false;

   if (!initialized) 
   {
      // Initialize the symbol engine.
      initialized = true;

      SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);
      if (SymInitialize (RemoteProcess, NULL, TRUE) == FALSE)
         return S_FALSE;

      initialized_success = true;
   }

   if (!initialized_success)
      return S_FALSE;

   // Manually created SYMBOL_INFO structure since the
   // maximum symbol length is dynamic.
   std::vector<char> symbol_buffer (sizeof (SYMBOL_INFO) + MAX_SYM_NAME * sizeof (char));

   // Loop through all stackframes.
   for (unsigned int i = 0; i < StackTrace->FrameCount; i++)
   {
      intptr_t address = StackTrace->Frames[i];
      if (address == 0)
         break;

      PSYMBOL_INFO symbol = (PSYMBOL_INFO)symbol_buffer.data();
      if (!GetSymbolFromFrameAddress (RemoteProcess, symbol, address))
         continue;

      // Symbol name.
      // Most likely a function name (if valid).
      std::string name = std::string (symbol->Name, symbol->NameLen);

      // We are not interested in allocations without any symbol name.
      // Either an allocation has a symbolic reference to our code or some APIs but 'unknown'
      // symbols are not interesting for our use-case.
      if (name.empty ())
         continue;

      if (name == "uberHeapAlloc" || name == "uberHeapFree")
         continue;

      // Now optionally get the source code file and line number.
      std::pair<std::string, DWORD> source = GetSymbolSourceFile (RemoteProcess, address);
      if (source.first.size ())
      {
         // Source Code information is available.
         SymbolStackTrace.push_back ({ name, source.first, source.second });
      }
      else
      {
         // Source Code information is not available.
         SymbolStackTrace.push_back ({ name, std::string(), 0 });
      }
   }

   return S_OK;
}