#include <iostream>
#include <string>

#include <Windows.h>

void UpdateConsoleTitle (int count)
{
   std::string str = std::to_string (count);
   SetConsoleTitleA (str.c_str ());
}

int print_something_useful () 
{
   static int leak_count = 0;

   char* buf = new char[1024];
   memset (buf, 0, 1024);
   strcpy_s (buf, 1024, "I am a leak, or not?");

   if (leak_count % 2 == 0)
   {
      delete[] buf;
   }

   return ++leak_count;
}

///
/// Entrypoint
/// This application is to demonstrate a simple memory leak.
///
int main(int argc, char** argv)
{
   UNREFERENCED_PARAMETER (argc);
   UNREFERENCED_PARAMETER (argv);

   while (true)
   {
      printf ("press [ENTER] to leak memory; otherwise press [any] key to exit..");
      
      int c = std::getc (stdin);
      if (c == 0xA)
      {
         UpdateConsoleTitle (print_something_useful ());
      }
      else
      {
         printf ("exiting..\n");
         Sleep (1000);
         break;
      }
   }

   return 0;
}