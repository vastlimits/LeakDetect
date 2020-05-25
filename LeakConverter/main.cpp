#include <Windows.h>

#include <iostream>

#include "libLeak.h"
#include "LeakObject.h"
#include "LeakFileStream.h"

#include <optional>
#include <filesystem>
#include <unordered_set>
#include <unordered_map>

void GenerateSQLite (const std::string& input);    // GenerateSQLite.cpp
void GenerateCSVFile (const std::string& input);   // GenerateCSV.cpp

///
/// Application class
/// Handles arguments and start convert tasks.
///
class Application
{
   std::optional<std::string> optInputFile;
   std::optional<bool> optGenerateCSV;
   std::optional<bool> optGenerateSQLite;
   std::optional<bool> optPrintHelp;

public:
   Application (int argc, char** argv)
   {
      ParseCommandLineArguments (argc, argv);
   }

   int Execute ()
   {
      return ExecuteApplication();
   }

private:

   ///
   /// Parses given command line arguments.
   ///
   void ParseCommandLineArguments (int argc, char** argv)
   {
      for (int i = 0; i < argc; i++)
      {
         const char* argument = argv[i];
         if (strcmp (argument, "--input") == 0 && (i + 1) < argc)
         {
            optInputFile = std::string (argv[i + 1]);
         }
         else if (strcmp (argument, "--csv") == 0)
         {
            optGenerateCSV = true;
         }
         else if (strcmp (argument, "--sqlite") == 0)
         {
            optGenerateSQLite = true;
         }
         else if (strcmp (argument, "--help") == 0)
         {
            optPrintHelp = true;
         }
      }
   }

   ///
   /// Returns zero on success, otherwise a numeric error code.
   ///
   int ExecuteApplication ()
   {
      // Determines if a valid option is set.
      bool has_valid_option = 
         optGenerateCSV.has_value () || optGenerateSQLite.has_value ();

      // Print help if no option is selected or --help was requested.
      if (!has_valid_option || (optPrintHelp.has_value() && optPrintHelp.value ()))
      {
         PrintHelp ();
         return 1;
      }

      if (!optInputFile.has_value () ||
         optInputFile.value ().empty ())
      {
         std::cerr << "Missing input file. Use --input to specify a Leak database." << std::endl;
         return 1;
      }

      // Convert Leak.db to CSV if required.
      if (optGenerateCSV.has_value () && optGenerateCSV.value ())
      {
         GenerateCSVFile (optInputFile.value ());
      }

      // Convert native dat to SQLite if required.
      if (optGenerateSQLite.has_value () && optGenerateSQLite.value ())
      {
         GenerateSQLite (optInputFile.value ());
      }

      return 0;
   }

   /// Helper method to print a given option.
   void PrintOption (const char* option, const char* text)
   {
      printf ("  %-10s\t%-40s\n", option, text);
   }

   /// 
   /// Prints usage information.
   ///
   void PrintHelp ()
   {
      std::cout << "USAGE" << std::endl;
      std::cout << "LeakConvert.exe --input Leak.db OPTION(S)" << std::endl;
      std::cout << std::endl;
      std::cout << "OPTIONS" << std::endl;
      PrintOption ("--help", "Prints this help text.");
      PrintOption ("--csv", "Convert the input file to multiple CSV files.");
      PrintOption ("--sql", "Convert the input file to a Sqlite3 compatible .sql file.");
   }
};

///
/// Entrypoint
///
int main(int argc, char** argv)
{
   Application app (argc, argv);
   return app.Execute ();
}