#include "sqlite3/sqlite3.h"

#include <iostream>
#include <fstream>
#include <chrono>
#include <string>
#include <filesystem>

#include <libLeak.h>
#include <LeakObject.h>
#include <LeakFileStream.h>

namespace statements
{
   const char* CreateAllocationTable = R"(
      CREATE TABLE "ALLOCATION" (
	      "AllocationID"	         INTEGER,
	      "StacktraceID"	         INTEGER,
         "Pointer"               INTEGER,
	      "Size"	               INTEGER,
	      "AllocationTimestamp"	INTEGER,
	      "FreeTimestamp"	      INTEGER,
         "Freed"                 INTEGER,
	      PRIMARY KEY("AllocationID")
      );
   )";

   const char* CreateStackEntryTable = R"(
      CREATE TABLE "STACKENTRY" (
	      "ID"	               INTEGER PRIMARY KEY AUTOINCREMENT,
	      "StackTraceID"	      INTEGER NOT NULL,
	      "StackTraceIndex"	   INTEGER,
	      "ModuleBaseAddress"	INTEGER,
	      "FileName"	         TEXT,
	      "SymbolName"	      TEXT,
	      "LineNumber"	      INTEGER
      );
   )";

   const char* CreateIndexAllocationStackTraceID = R"(
      CREATE INDEX "IDX_AllocationStacktraceID" ON "ALLOCATION" (
	      "StacktraceID"
      );
   )";

   const char* CreateIndexAllocationFreed = R"(
      CREATE INDEX "IDX_AllocationFreed" ON "ALLOCATION" (
	      "Freed"
      );
   )";

   const char* CreateIndexStackEntryStackTraceID = R"(
      CREATE INDEX "IDX_StackEntryStackTraceID" ON "STACKENTRY" (
	      "StackTraceID"
      );
   )";

   const char* CreateIndexStackEntrySymbolName = R"(
      CREATE INDEX "IDX_StackEntrySymbolName" ON "STACKENTRY" (
	      "SymbolName"
      );
   )";

   const char* InsertAllocation = R"(
      INSERT INTO "ALLOCATION" 
         ("AllocationID","StacktraceID", "Pointer", "Size","AllocationTimestamp","FreeTimestamp","Freed") 
      VALUES 
         (?, ?, ?, ?, ?, ?, ?);
   )";

   const char* UpdateAllocationFree = R"(
      UPDATE "ALLOCATION" SET "Freed"=1, "FreeTimestamp"=? WHERE "AllocationID" = ?;
   )";

   const char* InsertStackEntry = R"(
      INSERT INTO "STACKENTRY"
         ("StackTraceID","StackTraceIndex","ModuleBaseAddress","FileName","SymbolName","LineNumber") 
      VALUES 
         (?, ?, ?, ?, ?, ?);
   )";

   const char* SelectAllocation = R"(
      SELECT AllocationID from ALLOCATION WHERE Pointer = ? AND Freed = 0 ORDER BY AllocationID ASC LIMIT 0, 1
   )";
}

class Sqlite
{
   sqlite3* db;
   std::filesystem::path base_dir;
   sqlite3_stmt* stmt_insert_allocation;
   sqlite3_stmt* stmt_update_allocation;
   sqlite3_stmt* stmt_insert_stackentry;
   sqlite3_stmt* stmt_select_allocation;

public:
   Sqlite (const std::filesystem::path& directory)
      : db(nullptr)
      , base_dir(directory)
      , stmt_insert_allocation(nullptr)
      , stmt_update_allocation(nullptr)
      , stmt_insert_stackentry(nullptr)
      , stmt_select_allocation(nullptr)
   {
   }

   ~Sqlite ()
   {
      if (stmt_insert_allocation)
      {
         sqlite3_finalize (stmt_insert_allocation);
         stmt_insert_allocation = nullptr;
      }

      if (stmt_update_allocation)
      {
         sqlite3_finalize (stmt_update_allocation);
         stmt_update_allocation = nullptr;
      }

      if (stmt_insert_stackentry)
      {
         sqlite3_finalize (stmt_insert_stackentry);
         stmt_insert_stackentry = nullptr;
      }

      if (stmt_select_allocation)
      {
         sqlite3_finalize (stmt_select_allocation);
         stmt_select_allocation = nullptr;
      }

      if (db)
      {
         sqlite3_close (db);
         db = nullptr;
      }
   }

   std::filesystem::path GetNextDatabaseFileName (const std::string& name_template)
   {
      int index = 1;
      std::filesystem::path fname;

      do
      {
         fname = base_dir / (name_template + "-" + std::to_string (index++) + ".db");
         std::string s = fname.string ();
         std::ifstream f(s.c_str());
         if (!f.good ())
            return fname;

      } while (true);
   }

   int update_pragmas ()
   {
      int rc;
      rc = sqlite3_exec (db, "PRAGMA JOURNAL_MODE=memory;", NULL, NULL, NULL);
      if (rc) goto Cleanup;

      rc = sqlite3_exec (db, "PRAGMA synchronous=OFF;", NULL, NULL, NULL);
      if (rc) goto Cleanup;

   Cleanup:
      return rc;
   }

   int create_indices ()
   {
      int rc;
      char* error = nullptr;

      rc = sqlite3_exec (db, statements::CreateIndexAllocationStackTraceID, NULL, NULL, &error);
      if (rc) goto Cleanup;

      rc = sqlite3_exec (db, statements::CreateIndexAllocationFreed, NULL, NULL, &error);
      if (rc) goto Cleanup;

      rc = sqlite3_exec (db, statements::CreateIndexStackEntryStackTraceID, NULL, NULL, &error);
      if (rc) goto Cleanup;

      rc = sqlite3_exec (db, statements::CreateIndexStackEntrySymbolName, NULL, NULL, &error);
      if (rc) goto Cleanup;

   Cleanup:
      return rc;
   }

   int begin_transaction ()
   {
      int rc;
      rc = sqlite3_exec (db, "BEGIN TRANSACTION;", NULL, NULL, NULL);
      return rc;
   }

   int end_transaction ()
   {
      int rc;
      rc = sqlite3_exec (db, "END TRANSACTION;", NULL, NULL, NULL);
      return rc;
   }

   void print_err_if_any (int rc)
   {
      if (rc)
      {
         std::cerr << "Error executing SQLite3 statement: " << sqlite3_errmsg(db) << std::endl;
      }
   }

   bool initialize ()
   {
      int rc;
      char* error = nullptr;

      std::filesystem::path fname_path = GetNextDatabaseFileName ("leak-sqlite");
      std::string fname = fname_path.string ();

      // create in memory database
      rc = sqlite3_open (fname.c_str(), &db);
      if (rc) goto Cleanup;

      rc = update_pragmas ();
      if (rc) goto Cleanup;

      rc = begin_transaction ();
      if (rc) goto Cleanup;

      // create tables
      rc = sqlite3_exec (db, statements::CreateAllocationTable, NULL, NULL, &error);
      if (rc) goto Cleanup;

      rc = sqlite3_exec (db, statements::CreateStackEntryTable, NULL, NULL, &error);
      if (rc) goto Cleanup;

      rc = end_transaction ();
      if (rc) goto Cleanup;

      // prepare update and insert statements
      rc = sqlite3_prepare_v2 (db, statements::InsertAllocation, -1, &stmt_insert_allocation, 0);
      if (rc) goto Cleanup;

      rc = sqlite3_prepare_v2 (db, statements::UpdateAllocationFree, -1, &stmt_update_allocation, 0);
      if (rc) goto Cleanup;

      rc = sqlite3_prepare_v2 (db, statements::InsertStackEntry, -1, &stmt_insert_stackentry, 0);
      if (rc) goto Cleanup;

      rc = sqlite3_prepare_v2 (db, statements::SelectAllocation, -1, &stmt_select_allocation, 0);
      if (rc) goto Cleanup;

   Cleanup:
      if (rc)
      {
         print_err_if_any (rc);
         if (error)
            sqlite3_free (error);
      }

      return rc == 0;
   }

   Sqlite& operator << (const libLeak::LeakObjectAllocation& object)
   {
      int rc;
      sqlite3_stmt* stmt = stmt_insert_allocation;

      static uint64_t allocationId = 1;

      rc = sqlite3_bind_int64 (stmt, 1, allocationId++);
      if (rc) goto Cleanup;
   
      rc = sqlite3_bind_int64 (stmt, 2, object.StacktraceId);
      if (rc) goto Cleanup;

#ifdef _WIN64
      rc = sqlite3_bind_int64 (stmt, 3, object.Pointer);
      if (rc) goto Cleanup;
#else
      rc = sqlite3_bind_int (stmt, 3, object.Pointer);
      if (rc) goto Cleanup;
#endif

      rc = sqlite3_bind_int64 (stmt, 4, object.PointerSize);
      if (rc) goto Cleanup;
   
      rc = sqlite3_bind_int64 (stmt, 5, object.Timestamp);
      if (rc) goto Cleanup;
   
      rc = sqlite3_bind_int64 (stmt, 6, 0); // Free Timestamp;
      if (rc) goto Cleanup;
   
      rc = sqlite3_bind_int64 (stmt, 7, 0); // Freed;
      if (rc) goto Cleanup;

      rc = sqlite3_step (stmt);
      if (rc != SQLITE_DONE) goto Cleanup;

      rc = sqlite3_clear_bindings (stmt);
      if (rc) goto Cleanup;
   
      rc = sqlite3_reset (stmt);
      if (rc) goto Cleanup;

   Cleanup:
      print_err_if_any (rc);
      return *this;
   }

   uint64_t GetAllocationIdentifierByPointer (intptr_t pointer)
   {
      int rc;
      sqlite3_stmt* stmt = stmt_select_allocation;

#ifdef _WIN64
      rc = sqlite3_bind_int64 (stmt, 1, pointer);
      if (rc) goto Cleanup;
#else
      rc = sqlite3_bind_int (stmt, 1, pointer);
      if (rc) goto Cleanup;
#endif

      rc = sqlite3_step (stmt);
      if (rc == SQLITE_ROW)
      {
         uint64_t result = sqlite3_column_int64 (stmt, 0);
         sqlite3_reset (stmt);
         return result;
      }
      else if (rc == SQLITE_DONE)
      {
         sqlite3_reset (stmt);
         return 0;
      }

   Cleanup:
      print_err_if_any (rc);
      return 0;
   }

   Sqlite& operator << (const libLeak::LeakObjectDeallocation& object)
   {
      uint64_t id = GetAllocationIdentifierByPointer (object.Pointer);
      if (id == 0)
         return *this;

      int rc;
      sqlite3_stmt* stmt = stmt_update_allocation;

      rc = sqlite3_bind_int64 (stmt, 1, object.Timestamp);
      if (rc) goto Cleanup;

      rc = sqlite3_bind_int64 (stmt, 2, id);
      if (rc) goto Cleanup;

      rc = sqlite3_step (stmt);
      if (rc != SQLITE_DONE) goto Cleanup;

      rc = sqlite3_clear_bindings (stmt);
      if (rc) goto Cleanup;
   
      rc = sqlite3_reset (stmt);
      if (rc) goto Cleanup;

   Cleanup:
      print_err_if_any (rc);
      return *this;
   }

   Sqlite& operator << (
      const std::pair<const libLeak::LeakObjectStacktrace&, 
      const std::vector<libLeak::SYMBOL_ENTRY>&> pair)
   {
      int rc = 0;
      sqlite3_stmt* stmt = stmt_insert_stackentry;

      const libLeak::LeakObjectStacktrace& object = pair.first;
      const std::vector<libLeak::SYMBOL_ENTRY>& entries = pair.second;

      int index = 0;
      for (const auto& entry : entries)
      {
         // StackTraceID
         rc = sqlite3_bind_int64 (stmt, 1, object.StacktraceId);
         if (rc) goto Cleanup;

         // StackTraceIndex
         rc = sqlite3_bind_int64 (stmt, 2, index++);
         if (rc) goto Cleanup;

         // ModuleBaseAddress
         rc = sqlite3_bind_int64 (stmt, 3, NULL);
         if (rc) goto Cleanup;

         // FileName
         rc = sqlite3_bind_text (stmt, 4, entry.file.c_str(), -1, NULL);
         if (rc) goto Cleanup;

         // SymbolName
         rc = sqlite3_bind_text (stmt, 5, entry.name.c_str(), -1, NULL);
         if (rc) goto Cleanup;

         // LineNumber
         rc = sqlite3_bind_int64 (stmt, 6, entry.line);
         if (rc) goto Cleanup;

         rc = sqlite3_step (stmt);
         if (rc != SQLITE_DONE) goto Cleanup;

         rc = sqlite3_clear_bindings (stmt);
         if (rc) goto Cleanup;
   
         rc = sqlite3_reset (stmt);
         if (rc) goto Cleanup;
      }

   Cleanup:
      print_err_if_any (rc);
      return *this;
   }
};

std::filesystem::path GetDirectoryFromInputFile (const std::string& input)
{
   std::filesystem::path input_path (input);
   return input_path.parent_path ();
}

void GenerateSQLite (const std::string& input)
{
   Sqlite db(GetDirectoryFromInputFile(input));
   if (!db.initialize ())
   {
      std::cerr << "Could not initialize target database." << std::endl;
      return;
   }

   int rc = db.begin_transaction ();
   if (rc)
   {
      db.print_err_if_any (rc);
      return;
   }

   FILE* fp = NULL;
   fopen_s (&fp, input.c_str (), "rb");
   if (fp == NULL)
   {
      std::cerr << "Could not open input file " << input << std::endl;
      return;
   }

   libLeak::LeakObject nextObject;
   libLeak::LeakFileStream stream (fp);

   libLeak::LeakObjectHeader header{ 0 };
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
         libLeak::LeakObjectAllocation obj{ 0 };
         if (stream.ParseAllocation (obj))
         {
            db << obj;
         }
         break;
      }

      // Serialize Deallocations
      case (int)libLeak::LeakObjectType::Deallocation:
      {
         libLeak::LeakObjectDeallocation obj{ 0 };
         if (stream.ParseDeallocation (obj))
         {
            db << obj;
         }
         break;
      }

      // Serialize Stacktrace
      case (int)libLeak::LeakObjectType::Stacktrace:
      {
         libLeak::LeakObjectStacktrace obj{ 0 };
         std::vector<libLeak::SYMBOL_ENTRY> symbols;
         if (stream.ParseStacktrace (obj, symbols))
         {
            db << std::pair<libLeak::LeakObjectStacktrace, std::vector<libLeak::SYMBOL_ENTRY>> (obj, symbols);
         }
         break;
      }

      // The Header and Session is not particular interesting in a Sqlite dump.
      // The only information of value is the starting Timestamp; however the first Allocation
      // Timestamp should be enough for ongoing analysis.
      //
      case (int)libLeak::LeakObjectType::Header:
      case (int)libLeak::LeakObjectType::Session:
      default:
         if (!stream.SkipObject (nextObject))
         {
            std::cerr << "Skipping object pointed to invalid position in file.\n";
            goto Exit;
         }
         break;
      }
   }

Exit:
   rc = db.end_transaction ();
   if (rc) goto Cleanup;

   rc = db.create_indices ();
   if (rc) goto Cleanup;

Cleanup:
   db.print_err_if_any (rc);
}