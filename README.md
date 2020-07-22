# LeakDetect

> A Windows Memory Instrumentation tool to detect memory leaks for long-running applications.
---
![CI](https://github.com/vastlimits/LeakDetect/workflows/CI/badge.svg)


## Table of Contents

- [Installation](#installation)
- [How does it work?](#how-does-it-work)
- [Why another tool?](#why-another-tool)
- [Platforms](#platforms)
- [Usage](#usage)
- [Limitations](#limitations)
- [License](#license)
- [Third Party](#third-party)

## Installation
- Download the latest version from [Releases](https://github.com/vastlimits/LeakDetect/releases).
- Choose `LeakDetect-x64` or `LeakDetect-x86` depending on your instrumentation target platform.

## How does it work?
The LeakDetect tool suite uses [Microsoft Detours](https://github.com/microsoft/detours) to instrument all allocations in a target process that calls [HeapAlloc](https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapalloc) and [HeapFree](https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapfree). Memory allocations such as `new` and `malloc` or `calloc` usually end up calling `HeapAlloc`. Deallocations end up in calling `HeapFree`.

<p align="center">
  <img src="/docs/diagram_flow.png" />
</p>

Each intercepted allocation (and deallocation) is synchronized to a single thread. Then, the stacktrace is captured using `RtlCaptureStacktrace` and a global Windows event is set.

The `LeakMonitor` application listens to this event and collects all necessary information using `ReadProcessMemory`. Then, the global signal is released so that the target application can continue executing and all collected information is post-processed in `LeakMonitor`.

This procedure adds a *lot of overhead* to the target application, especially the symbol collection that is happening while the target application is interrupted.

## Why another tool?
There are many great tools to capture memory leaks available for Windows. However, even [VLD](https://kinddragon.github.io/vld/) or [DebugDiag](https://www.microsoft.com/en-us/download/details.aspx?id=58210) did not meet our requirements, at least for one special issue we were analyzing. While developing our new major version of [uberAgent](https://uberagent.com) we noticed a memory leak that increased memory usage by ~1MB in 24 hours.

We spent a lot of time finding this leak using the mentioned and other tools such as ETW tracing, but without success. While `DebugDiag` is a great tool that intercepts all allocations, it crashed the Agent after a couple of hours. 

Because of this, we developed this leak detection tool that gives visibility to:

- Allocations including stack trace, pointer, size, and timestamp.
- All deallocations.
- Hot code paths that produce the most allocations/deallocations.

The results are saved to a binary file format that can be converted to `CSV` and `Sqlite` databases for further analysis.

## Platforms
The LeakDetect tool is compiled and deployed to x86 and x64 architectures. Use the matching architecture to analyze your target application.

## Usage
Start the `LeakMonitor` application from an elevated command line and attach it to a privileged process by **name** or **pid**.

The target process should be linked with debug information and if possible without any optimization or even a debug build to get 
detailed stack traces.

To inject the monitor to a 64 Bit process with PID 1234 use the following command:

```cmd
LeakMonitor.X64.exe --inject 1234
```

To inject the monitor to a 64 bit process by process-name use the following command:

```cmd
LeakMonitor.X64.exe --inject Leak.X64.exe
```

To inject into 32 bit processes use the `LeakMonitor.X86.exe`. While running the application some output is generated such as the following:

```cmd
C:\Users\demo\Downloads\LeakDetect-x64>LeakMonitor.X64.exe --inject Leak.X64.exe
2020-05-25.14:36:54: Create directory C:\Users\demo\Downloads\LeakDetect-x64\Logs\107060 - 2020-05-25.14-36
2020-05-25.14:36:54: Initialized QueuedFilesystemBackend for PID 107060
2020-05-25.14:36:54: Created event Global\vl.leak.107060.interrupt.continue
2020-05-25.14:36:54: Created event Global\vl.leak.107060.start
2020-05-25.14:36:54: Created event Global\vl.leak.107060.stop
2020-05-25.14:36:54: Library was injected into process 107060
2020-05-25.14:36:54: Opened event Global\vl.leak.107060.interrupt
2020-05-25.14:36:54: Opened event Global\vl.leak.107060.start.confirm
2020-05-25.14:36:54: Opened event Global\vl.leak.107060.stop.confirm
2020-05-25.14:36:54: Profiling started.
```

Once the target application has exited, the Leak Monitor application will finish processing all pending allocation events and stores all output to a binary file `C:\Users\demo\Downloads\LeakDetect-x64\Logs\107060 - 2020-05-25.14-36\Leak.dat`.

### Analysis
Use the `LeakConvert.X64.exe` executable to analyze `Leak.dat` and print or convert allocation and deallocation information.

### Analysis: Convert to CSV
Use `LeakConvert.X64.exe --csv --input "C:\Users\demo\Downloads\LeakDetect-x64\Logs\107060 - 2020-05-25.14-36\Leak.dat"` to export the report as CSV files.

This command creates three CSV files named:

- allocations.csv
- deallocations.csv
- stacktrace.csv


### Analysis: Convert to Sqlite
Use `LeakConvert.X64.exe --sqlite --input "C:\Users\demo\Downloads\LeakDetect-x64\Logs\107060 - 2020-05-25.14-36\Leak.dat"` to export the report as Sqlite file.


#### SQLite Examples

**Get a list of stack traces that may leak memory:**

```sql
SELECT 
	SUM(Freed) as 'Freed', COUNT(AllocationID) as 'Allocated', StacktraceID
FROM
	ALLOCATION
GROUP BY
	StacktraceID	
ORDER BY
	Allocated DESC, Freed ASC
```

This gives a result like this:

| Freed | Allocated | StacktraceID |
|---|---|---|
| 0 | 94 | 1436413219 |
| 25 | 49 | 2824743809 |
| ... | ... |

Now, looking through the stack traces you easily find the Leak that we have implemented in our example program.
You may experience that some allocations are pointing to a `StacktraceID` that does not exist in the serialized stack traces. 
This happens if there is no real stack trace available (and is usually not related to your application but some OS internals or runtime specific functions.)

```sql
SELECT 
	*
FROM
	STACKENTRY
WHERE
	StacktraceID = 2824743809;
```

This gives a result like this:

| # | ID | Idx | FileName | SymbolName | LineNumber |
|---|---|---|---|---|---|
| 1 | 2824743809 | 0 | minkernel\crts\ucrt\src\appcrt\heap\malloc_base.cpp | _malloc_base | 34 |
| 2 | 2824743809 | 1 | d:\agent\_work\6\s\src\vctools\crt\vcstartup\src\heap\new_scalar.cpp | operator new | 35 |
| 3 | 2824743809 | 2 | **C:\Development\Github\LeakDetect\Leak\Leak.cpp** | **main** | 42 |
| 4 | 2824743809 | 3 | d:\agent\_work\6\s\src\vctools\crt\vcstartup\src\startup\exe_common.inl | __scrt_common_main_seh | 288 |
| 5 | 2824743809 | 4 | | BaseThreadInitThunk | 0 |
| 6 | 2824743809 | 5 | | RtlGetAppContainerNamedObjectPath | 0 |
| 7 | 2824743809 | 6 | | RtlGetAppContainerNamedObjectPath | 0 |

Here we see, that **Leak.cpp** in function main at line **42** allocated memory that was not freed. Looking at the source code it calls
`print_something_useful` at this point. Looks like the compiler inlined this function since the first line in this function is the allocation.

## Limitations
Since the injected DLL and the monitor are talking to each other using global events, this requires administrator privileges in the target application. The limitation can be removed in the target process if the code is updated to use local events for non-privileged processes. Pull requests are highly appreciated since this is not a priority for us as of today.

- LeakMonitor must be started elevated (full administrator privileges).
- Target Application must be started elevated (full administrator privileges).

## License
MIT License 

## Third Party
This project uses the following third-party libraries/code snippets:

- [Microsoft Detours](https://github.com/microsoft/detours)
- [SQLite](https://www.sqlite.org/)
- [Mr. Nukealizer, Remote Process API](https://www.codeproject.com/tips/139349/getting-the-address-of-a-function-in-a-dll-loaded)
