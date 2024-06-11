
# DlliDetect

Detecting DLL Injection Threads Via Hooking LdrInitializeThunk.

## Technical Overview
Since most DLL injectors will result to creating a thread with **CreateRemoteThread** which comes down to **NtCreateThreadEx**, We can hook **LdrInitializeThunk** to catch the thread before it executes and get its thread start address, This is possible because the windows kernel jumps to **LdrInitializeThunk** when a thread is created.

## Resources
- [Dll Injection Detector - mq1n](https://github.com/mq1n/DLLThreadInjectionDetector) 

