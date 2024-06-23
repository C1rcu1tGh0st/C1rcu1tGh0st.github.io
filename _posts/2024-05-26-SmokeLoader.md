---
title: SmokeLoader Malware Analysis 
date: 2024-06-23 
categories: [malware analysis, ]
tags: [smokeloader, malware]     # TAG names should always be lowercase
---

# SmokeLoader Malware Analysis

SmokeLoader is primarily a loader which was first detected in 2011, and its main objective is to download or load a stealthier or more effective malware into the system. It increases its capability by adding new tactics and techniques regularly and constantly evolving with time.

The sample that is being analyzed here can be picked up from [02afba9405a5b480a7b1b80ec9abab41e462f8c30567f1926105a63eaf13e059](https://bazaar.abuse.ch/sample/02afba9405a5b480a7b1b80ec9abab41e462f8c30567f1926105a63eaf13e059/)

## Stage 1

In initial stage the main events that occur that needs our attention is a call to `VirtualAllocEx` which allocates memory and writes data into it, this is not yet the shellcode. This data is then passed as a parameter to a followup function which will manipulate the data and present the shellcode, finally there is a call to `EAX` which take us to the shellcode entry point. Also during the course to the shellcode entry point the malware introduces garbage api calls which can be spotted in below images too.


![](assets/ss/smokeloader/1.PNG) 
*Fig 1: Call to VirtualAllocEx and writing data to allocated buffer* 

![](assets/ss/smokeloader/2.PNG)
*Fig 2: call to shellcode data manipulation routine*

![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/3.PNG)
*Fig 3: Finally Call to EAX or Allocated Buffer which is the shellcode entrypoint*

## Shellcode 1

This shellcode calls 2 important functions 

* The first function takes a struct as parameter and later populates more members into it which are resolved API address, this function involves API hashing and PEB walking to resolve API's

![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/5.png)
*Fig 4: populating the structure*

![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/4.png) 
*Fig 5: Hashes being passed to resolving function*

![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/6.png)
*Fig 6: PEB walking to resolve api address of LoadLibraryA and GetProcAddress From Kernel32.dll*

![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/7.png)
*Fig 7: sll1AddHash32 hashing function*

This is how the populated structure looks like
```cpp

struct mw_struct_1 // sizeof=0x34
{
    _DWORD unk;
    _DWORD offset_or_address;
    _DWORD enc_shellcode_offset_0x6c1f;
    _DWORD seed;
    _DWORD LoadLibraryA;
    _DWORD GetProcAddress;
    _DWORD GlobalAlloc;
    _DWORD GetLastError;
    _DWORD Sleep;
    _DWORD VirtualAlloc;
    _DWORD CreateToolhelp32Snapshot;
    _DWORD Module32First;
    _DWORD CloseHandle;
};
```

* Once The structure gets populated it is passed as the parameter to the 2nd function, a call to `CreateToolhelp32Snapshot` and `Module32First` is done to get the first module of the process, another function is called after that, Here a call to `VirtualAlloc` is made, before that the 2nd shellcode data which can be found at offset which is a member of struct `enc_shellcode_offset_0x6c1f` this shell code data is decrypted using a xor decryption function, the `ms_rand()` function which takes a seed from the structure is used to generate keys for decrypting the bytes of shellcode data, further more this xor decrypted data is then passed to a decompression algorithm of some sort(I couldn't find the name of algo). The new shellcode(2nd layer) is written to the allocated buffer and then is `JMP` to the new shellcode.

![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/create32.png)
*Fig 8: getting the first module loaded*

![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/8.png)
*Fig 9: Call to xor decryption function and and VirtualAlloc and then the Decompression followed by JMP to Shellcode*

![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/10.png)
*Fig 10:  xor decryption function*

![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/9.png)
*Fig 11: ms_rand() function*

## Shellcode 2

Layer 2 shellcode has the objective to inject the embedded PE file(stage 2 binary) in stage 1 binary using process hollowing injection technique. To complete this objective malware crafts another structure which majorly has API's, this time stack strings are used to resolve API's by making use of other API like `LoadLibraryA` and `GetProcAddress` these both are resolved using API hashing mentioned in shellcode 1(layer 1), the structure also has the address to embedded PE file.

```cpp
struct mw_struct // sizeof=0x90
{
    _DWORD LoadLibraryA;
    _DWORD GetProcAddress;
    _DWORD gap_8;
    _DWORD embedded_pe_offset_0x15a0;
    _DWORD gap_10;
    _DWORD MessageBoxA;
    _DWORD GetMessageExtraInfo;
    _DWORD gap_1c;
    _DWORD WinExec;
    _DWORD CreateFileA;
    _DWORD WriteFile;
    _DWORD CloseHandle;
    _DWORD CreateProcessA;
    _DWORD GetThreadContext;
    _DWORD VirtualAlloc;
    _DWORD VirtualAllocEx;
    _DWORD VirtualFree;
    _DWORD ReadProcessMemory;
    _DWORD WriteProcessMemory;
    _DWORD SetThreadContext;
    _DWORD ResumeThread;
    _DWORD WaitForSingleObject;
    _DWORD GetModuleFileNameA;
    _DWORD GetCommandLineA;
    _DWORD RegisterClassExA;
    _DWORD CreateWindowExA;
    _DWORD PostMessageA;
    _DWORD GetMessageA;
    _DWORD DefWindowProcA;
    _DWORD GetFileAttributesA;
    _DWORD gap78;
    _DWORD NtUnmapViewOfSection;
    _DWORD NtWriteVirtualMemory;
    _DWORD GetStartupInfoA;
    _DWORD VirtualProtectEx;
    _DWORD ExitProcess;
};
```

After crafting the structure the malware calls a subroutine where it calls GetFileAttributesA to get system attributes of a non existing file named `apfHQ` my best guess is this some sort of anti-emulation

![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/11.png)
*Fig 12: Calls GetFileAttributesA to perform anti-emulation*

The shellcode creates a windows class by making use of 2 API's which are `RegisterClassExA` and `CreateWindowExA` with a class name `saodkfnosa9uin`

![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/12.png)
*Fig 13: Creates a Windows Class*

Now the shellcode calls a function that will inject the PE by making use of Process Hollowing technique 

![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/13.png)
*Fig 14: Creates another process in suspended state*

![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/14.png)
*Fig 15: Unmaps the memory and writes new binary*

![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/15.png)
*Fig 16: Sets the thread context and resume thread in new process*


## Stage 2

Stage 2 binary is full of anti-analysis tricks we starts with [Opaque predicate](https://en.wikipedia.org/wiki/Opaque_predicate) and this [blog](https://n1ght-w0lf.github.io/malware%20analysis/smokeloader/#opaque-predicates) has good walk through of how to deal with it and another blog from [OALABS](https://research.openanalysis.net/smoke/smokeloader/loader/config/yara/triage/2022/08/25/smokeloader.html) which can help in dealing this.

![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/16.png)
*Fig 17: signs of Opaque predicate*

The code can be cleaned up by patching the those conditional jumps to a `JMP` instruction and `NOP` out the rest of junk bytes this script from [n1ght-w0lf's Blog](https://n1ght-w0lf.github.io/malware%20analysis/smokeloader/#opaque-predicates) can be used to do this.

```python

import idc

ea = 0
while True:
    ea =  min(idc.find_binary(ea, idc.SEARCH_NEXT | idc.SEARCH_DOWN, "74 ? 75 ?"),  # JZ / JNZ
              idc.find_binary(ea, idc.SEARCH_NEXT | idc.SEARCH_DOWN, "75 ? 74 ?"))  # JNZ / JZ
    if ea == idc.BADADDR:
      break
    idc.patch_byte(ea, 0xEB)  # JMP
    idc.patch_byte(ea+2, 0x90)  # NOP
    idc.patch_byte(ea+3, 0x90)  # NOP

```

### Function Decryption

once the obfuscation has been patched according to the above mention blog we should encounter a xor function decryption routine the malware encrypts and decrypts few functions on demand

the function takes 2 parameters an `offset` and `size of encrypted bytes`  decryption is a single byte xor, but the key is passed as a DWORD to `edx` and we use only the LSB that is `0xFE` as xor key

```nasm
push    604008FEh
pop     edx

```

#![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/funcdec/1.png)
#*Fig 17: xor function decryption routine*

using this script from the above mentioned blog by just changing the offset and key

```python

def xor_chunk(offset, n):
    ea = 0x400E00 + offset
    for i in range(n):
        byte = ord(idc.get_bytes(ea+i, 1))
        byte ^= 0xfe
        idc.patch_byte(ea+i, byte)

xor_chunk(0x1205, 0x4d)# this is the offset and size of first function i came across
```

### API Resolution 

API hashing is performed to resolve the API's, djb2 hashing algorithm is used as hashing function one thing to notice is the hashes are encrypted with `604008FEh` as the key to xor decrypt the hashes. this [blog](https://medium.com/@farghly.mahmod66/smoke-loader-analysis-1f1442809802) has a good script to decrypt the hashes and patch it in ida

```python
import idc 
import ida_bytes
start = #start of hash table
num_api = #
 
        

for i in range(0,num//4*4, 4):

    x_hash = idc.get_bytes(start +i,4) 
    
    xored_hash = int.from_bytes(x_hash, byteorder='little') ^ 0x604008FE

    ida_bytes.patch_dword(start + i, xored_hash)        



```

![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/funcdec/2.png)
*Fig 18: djb2 hashing function used to resolve API's*

smokeldr intended to resolve API's from `ntdll.dll`, `kernel32`, `user32`, `advapi32`, `shell32` interestingly for `ntdll.dll`  it maps the dll and resolve API's from there, this is an anti-hooking method used since AV's usually hooks certain API's from `ntdll.dll`

![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/funcdec/3.png)
*Fig 18: Ntdll.dll anti-hooking*

<details open>
<summary>Resolved API and Hashes</summary>

<br>
ntdll.NtTerminateProcess(0xF779110F)<br>
ntdll.NtClose(0xFD507ADD)<br>
ntdll.LdrLoadDll(0x64033f83)<br>
ntdll.RtlInitUnicodeString(0x60a350a9)<br>
ntdll.RtlZeroMemory(0x8a3d4cb0)<br>
<br>
kernel32.GetModuleHandleA(0x9cbd2a58)<br>
kernel32.Sleep(0xd156a5be)<br>
kernel32.GetModuleFileNameW(0x8acccdc3)<br>
kernel32.ExpandEnvironmentStringsW(0x057074bb)<br>
kernel32.lstrcatW(0x2ab51a99)<br>
kernel32.CreateFileW(0x5e6f8810)<br>
kernel32.CreateFileMappingW(0x5b3f901c)<br>
kernel32.MapViewOfFile(0x4db4c713)<br>
kernel32.LocalAlloc(0xeda647bb)<br>
kernel32.LocalFree(0x742c61b2)<br>
<br>
user32.GetForegroundWindow(0x5a6c9878)<br>
user32.GetShellWindow(0xd454e895)<br>
user32.GetWindowThreadProcessId(0x576a5801)<br>
user32.wsprintfW(0x0bafd3f9)<br>
user32.GetKeyboardLayoutList(0x04e9de30)<br>
<br>
advapi32.OpenProcessToken(0x74f5e377)<br>
advapi32.GetTokenInformation(0x696464ac)<br>
<br>
shell32.ShellExecuteExW(0xf8e40384)<br>
<br>
ntdll.NtOpenProcess(0x507bcb58)<br>
ntdll.NtCreateSection(0xd5f23ad0)<br>
ntdll.NtMapViewOfSection(0x870246aa)<br>
ntdll.NtAllocateVirtualMemory(0x5a0c2ccc)<br>
ntdll.NtDuplicateObject(0x94a6b139)<br>
ntdll.NtQuerySystemInformation(0xb83de8a8)<br>
ntdll.NtQueryInformationProcess(0xd6d488a2)<br>
ntdll.NtOpenKey(0xc29efe42)<br>
ntdll.NtQueryKey(0xa9475346)<br>
ntdll.NtEnumerateKey(0xb6306996)<br>
ntdll.RtlCreateUserThread(0x22dd8542)<br>
ntdll.strstr(0xaf0f4637)<br>
ntdll.wcsstr(0xbb629f0b)<br>
ntdll.tolower(0xee10d8f1)<br>
ntdll.towlower(0xf7660ba8)<br>
</details>
<br>

the API structure looks like this

```
struct iat
{
  DWORD ptr_NtTerminateProcess;
  DWORD ptr_NtClose;
  DWORD ptr_LdrLoadDll;
  DWORD ptr_RtlInitUnicodeString;
  DWORD ptr_RtlZeroMemory;
  DWORD null1;
  DWORD ptr_GetModuleHandleA;
  DWORD ptr_Sleep;
  DWORD ptr_GetModuleFileNameW;
  DWORD ptr_ExpandEnvironmentStringsW;
  DWORD ptr_lstrcatW;
  DWORD ptr_CreateFileW;
  DWORD ptr_CreateFileMappingW;
  DWORD ptr_MapViewOfFile;
  DWORD ptr_LocalAlloc;
  DWORD ptr_LocalFree;
  DWORD null2;
  DWORD ptr_GetForegroundWindow;
  DWORD ptr_GetShellWindow;
  DWORD ptr_GetWindowThreadProcessId;
  DWORD ptr_wsprintfW;
  DWORD ptr_GetKeyboardLayoutList;
  DWORD null3;
  DWORD ptr_OpenProcessToken;
  DWORD ptr_GetTokenInformation;
  DWORD null4;
  DWORD ptr_ShellExecuteExW;
  DWORD null5;
  DWORD ptr_NtOpenProcess;
  DWORD ptr_NtCreateSection;
  DWORD ptr_NtMapViewOfSection;
  DWORD ptr_NtAllocateVirtualMemory;
  DWORD ptr_NtDuplicateObject;
  DWORD ptr_NtQuerySystemInformation;
  DWORD ptr_NtQueryInformationProcess;
  DWORD ptr_NtOpenKey;
  DWORD ptr_NtQueryKey;
  DWORD ptr_NtEnumerateKey;
  DWORD ptr_RtlCreateUserThread;
  DWORD ptr_strstr;
  DWORD ptr_wcsstr;
  DWORD ptr_tolower;
  DWORD ptr_towlower;
};

```



### Skip Infection On Russian And Ukraine Machines

Smokeldr loves to avoid infecting Russian and Ukraine Machines this is one of the well known feature in smokeldr, it is done by making a call to `GetKeyboardLayoutList` and checking for specific id's `Ukranian(0x422)` and `Russian(0x419)` 

![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/funcdec/4.png)
*Fig 19: Skip infection*



### Privilege Checks

Malware checks for current running integrity level and runs the malware with higher privilege if it finds it is currently running as low privilege, it make use of `OpenProcessToken` and `GetTokenInformation` to check the integrity level and compare the `TokenAuditPolicy` value to 0x2000(SECURITY_MANDATORY_MEDIUM_RID ) if its below the value it means low integrity level in that case the malware make use of `ShellExecuteExW` to run the malware under WMIC(Windows Management Instrumentation Command-line).

![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/funcdec/5.png)![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/funcdec/6.png)
*Fig 20: Check Privilege and run as admin*

### Anti-Emulation And Anti-VM Check

Before injecting the payload the malware runs bunch of anti-vm and anti-emulation checks, 

#### Checking for a Non Existing file
Smokeldr check for a non-existing file `7869.vmt` to see if it return true, in normal condition it returns an error but if its ran in an emulator it would return a handle or in this case pointer to string there by detecting the presence an emulator.

![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/funcdec/7.png)
*Fig 21: searching for 7869.vmt in module filename to detect emulator*

#### ProcessDebugPort Check
By calling `NtQueryInformationProcess` with `ProcessDebugPort` as `ProcessInformationClass` parameter the malware checks for debugger port number if a debugger is present, the call returns a non zero value

![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/funcdec/8.png)
*Fig 22: Querying the ProcessDebugPort*

#### Sandbox And AV Modules Checks

Malware checks for specific dlls sbidedll(Sandboxie), aswhook(Avast) and snxhk(Symantec) if its loaded into smokeldr memory space

![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/funcdec/9.png)
*Fig 23: specific dll checks*

#### Registry Check

Smokeldr enumerates all subkeys of 

* \REGISTRY\MACHINE\System\CurrentControlSet\Enum\IDE 

* \REGISTRY\MACHINE\System\CurrentControlSet\Enum\SCS

converts them to lowercase and search for 

`qemu`, `virtio`, `vmware`, `vbox`, `xen` these strings are related to vm's and emulators

![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/funcdec/10.png)
*Fig 24: enumerating registry keys for vm checks*

![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/funcdec/11.png)
*Fig 25: enumerating registry keys for vm checks*

![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/funcdec/12.png)
*Fig 26: enumerating registry keys for vm checks*

![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/funcdec/13.png)
*Fig 27: enumerating registry keys for vm checks*


#### Process And Driver Checks

Smokeldr call NtQuerySystemInformation to gain SystemProcessInformation, once it gets the process information of all running process it compares name with 

```
qemu-ga.exe
qga.exe
windanr.exe
vboxservice.exe
vboxtray.exe
vmtoolsd.exe
prl_tools.exe
```
![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/funcdec/14.png)
*Fig 28: gets SystemProcessInformation*

![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/funcdec/15.png)
*Fig 29: process that are compared*


smokeldr again calls NtQuerySystemInformation now to get SystemModuleInformation once it gets all drivers or modules it compares the name with

```
vmci.s
vmusbm
vmmous
vm3dmp
vmrawd
vmmemc
vboxgu
vboxsf
vboxmo
vboxvi
vboxdi
vioser

```

![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/funcdec/16.png)
*Fig 30: gets SystemModuleInformation*

![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/funcdec/17.png)
*Fig 31: modules that are compared*


### Stage 3 Injection 

Once all the checks has been done the malware checks for current machine architecture by getting the value in `GS` segment register `GS` register will contain 0 if its x86 machine and in x64 it will contain a positive value. once it figured out architecture it will decrypt the payload 

![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/injection/1.png)
*Fig 32: checking the architecture and determining the payload*

the data is encrypted by a hard coded xor key `0x604008FE` decryption is multiple of 4 and if there is any tailing byte its decrypted by a single byte key `0xFE` we could use the script from [OALABS](https://research.openanalysis.net/smoke/smokeloader/loader/config/yara/triage/2022/08/25/smokeloader.html) to get the payload, once the payload is extracted it is decompressed by LZSA2 algorithm we can use the tool from this repo [emmanuel-marty](https://github.com/emmanuel-marty/lzsa) to decompress it.
use the command `lzsa.exe -d -r -f 2 filename outfilename`


The third stage is injected to explorer.exe, smokeldr calls `GetShellWindow` to get a handle to explorer.exe and `GetWindowThreadProcessId ` to get its PID once that attained it calls `NtOpenProcess` and duplicates the handle of explorer.exe by calling `NtDublicateObject` then it create a section using `NtCreateSection` on with READ_WRITE permission and maps it to malware process address space and explorer, then it creates another section with PAGE_EXECUTE_READWRITE and maps that too after that it writes the payload to this section, then it call `RtlCreateUserThread`  to create a new thread in explorer.exe and sets start address as payload address.

![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/injection/2.png)

![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/injection/3.png)

![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/injection/4.png)

![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/injection/5.png)
*Fig 33: injecting payload*


## Stage 3

Taking a look at stage 3 binary we can see that its PE header is destroyed if we try to load this in ida we would get messed up alignments when it comes to address and offsets to fix that we can use HxD or any other hex editor to carve out section specifically and load it in ida and re-base it accordingly. In the following image we see the code starts at offset 0x400 we can copy the data from there to where it ends which is 0x3580 we can save these byte into a new file and load it in ida for better results, this will help to locate encrypted string table and c2 config once re-based properly

![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/stage3/1.png)
*Fig 34: code section starting at offset 0x400 that we are interested*

![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/stage3/2.png)
*Fig 35: end of code section at offset 0x3580 that we are interested*

we can spot RC4 function being used while looking through the binary, checking xref of rc4 function we lands in a function where we can spot the encrypted data and decryption key address but its little messed up to fix it we need to re-base the binary taking a look at fig:37 we can see address of key is at `0x100012B0` and address of encrypted data is at `0x100012B4` we need re-base the binary at `0x10001000` to get this address resolved, once done it will be easy to navigate the binary.

![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/stage3/3.png)
*Fig 36: rc4 function*

![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/stage3/4.PNG)
*Fig 37: string table decryption function*


### Decrypting String Table

the string table is aligned in this manner the first byte of the encrypted_string_table is the length of first encrypted string followed by encrypted string and it continues we can use the script from [OALABS](https://research.openanalysis.net/smoke/smokeloader/loader/config/yara/triage/2022/08/25/smokeloader.html) to decrypt the strings

![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/stage3/5.png)
*Fig 38: string table alignment*



```python
#credits - OALABS
import struct
import binascii

enc_string = '2D168CA68DFD7447C17CFEB723FDC6B20FDD93C1A142EAA49B46E857688329E0B60884228FA8590DA0921BA84E5B242D97B489F92F1A8B44DDAD6EE8C6AE07D782B29A49EDAE855EE81C26A73CF5E70A9F248F0C1F9CA49CFE275BDC36F4A861093297B19CFA270780220B0E94A79AE720379D71EAA10D229DAA8DE2211A8B6ABEA175FF060B8BB78FBD7C081F9CA49CFE275BDC060B8ABE90E120051194B7CEBC070991BC95FA3A1806098BE0A2BD7C061A96A19CFE27070D90B791E27D5A0A0D8EB1ABEB3C1B8777FE07289DA08EE7210604509ABB89045B8B94BB045BC8E0850A5B8BF7CDB6164DDE20C80C5BF8A1FDD24E4DEE7090B70D085BF8A1FDAB4E1BEE1C0CF8B7FDE94E1BEE6E90B60DA9A9EF6891F6C1D35499EBF7158D1B06125BF893FDDE4E38EE5C90850DCEA99C6894F60C5BF886FDCB4E25EE4890E10D0850F8B7FDF64E0DEE0850F8B6FDE24E04EE0850F8B0FDEF4E1CEE2044F888FDE14E06EE7D90EA0DD3A9B968D4F680D35399A2F7568D01068744F78B082EF89DFDDD4E3CEE5E3DF8BDFDE04E1CEE7D90AA0DEEA9F068E5F697D35799AEF70A8D48068344F58B15ED2DFDAE2A01C68735BF215F7C273BD52CDD6F77B6DB5531259FF8FC74B1DE06999708BC8BCA9A6D48FE7E5D9C64C262AC2AF884715A7356499D93A9340811F8A2FDEB4E06EE1036F8BDFDFD4E1CEE2290E40DBFA9AE680A2EF886FDBF4E58EE5590264FF8EBFDB74E51EE3590F50DABA9F06882F6DED37399FBF7008D5206D244B58B5FED71FDF72A4238F8BBFDFC4E0DEE7E90AB0DE2A9FD68F5F68BD34199AAF7458D04069644A58B27ED33FDA82A15C69535AE21447C683BFA2C956F6AB698553225C8F8AE74F4DE1399443FF8B1FDED4E0DEE6890B00DA0A9FD689BF6C1D30D99C6F73A8D3A068744E38B00ED33FDA22A10C6DC35EB215E7C3C3BCF2C826F35B6D9556925CDF8D874B9DE1399D708463FF8B1FDED4E0DEE6890B00DA0A9FD689BF6C1D30D99C6F73A8D3A068744E38B00ED33FDA22A10C6DC35EB215E7C3C3BCF2C826F7CB6CC556925C7F8AE74CFDE45998B08E18B0850F8B1FDE14E05EE0850F8BDFDFC4E0FEE0850F8BCFDEB4E1CEE000000F7E6C57213B7F7B81453ED770E1C3DBD1450E7E83171DFCE1762DF01FAB79B8B859DC25847268317378BF5AE05E4D6A4E37EE78C37BEC16119F4DD5DFBC729A34E02CBCFEF47EFE0'


str_data = binascii.unhexlify(enc_string)
key = struct.pack('<I', 0x993E81CB)

def rc4crypt(data, key):
    #If the input is a string convert to byte arrays
    if type(data) == str:
        data = data.encode('utf-8')
    if type(key) == str:
        key = key.encode('utf-8')
    x = 0
    box = list(range(256))
    for i in range(256):
        x = (x + box[i] + key[i % len(key)]) % 256
        box[i], box[x] = box[x], box[i]
    x = 0
    y = 0
    out = []
    for c in data:
        x = (x + 1) % 256
        y = (y + box[x]) % 256
        box[x], box[y] = box[y], box[x]
        out.append(c ^ box[(box[x] + box[y]) % 256])
    return bytes(out)

ptr = 0
while ptr <= 0x319:
    str_len = str_data[ptr]
    print(rc4crypt(str_data[ptr+1:ptr+1+str_len], key).replace(b'\x00',b''))
    ptr = ptr+1+str_len




```

```
b'https://dns.google/resolve?name=microsoft.com'
b'Software\\Microsoft\\Internet Explorer'
b'advapi32.dll'
b'Location:'
b'plugin_size'
b'\\explorer.exe'
b'user32'
b'advapi32'
b'urlmon'
b'ole32'
b'winhttp'
b'ws2_32'
b'dnsapi'
b'shell32'
b'svcVersion'
b'Version'
b'.bit'
b'%sFF'
b'%02x'
b'%s%08X%08X'
b'%s\\%hs'
b'%s%s'
b'regsvr32 /s %s'
b'%APPDATA%'
b'%TEMP%'
b'.exe'
b'.dll'
b'.bat'
b':Zone.Identifier'
b'POST'
b'Content-Type: application/x-www-form-urlencoded'
b'open'
b'Host: %s'
b'PT10M'
b'1999-11-30T00:00:00'
b'Firefox Default Browser Agent %hs'
b'Accept: */*\r\nReferer: http://%S%s/'
b'Accept: */*\r\nReferer: https://%S%s/'
b'.com'
b'.org'
b'.net'

```

## Config Extraction

finding more xref of RC4 function will lead to c2 url decryption routine, there is a structure that has pointers to encrypted c2 url data the encrypted data is aligned differently for c2's first is the length of encrypted data, 4byte decryption key followed by encrypted data,
in this sample there is only two c2 url in the structs but it may vary in other samples of smokeldr

![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/stage3/7.png)
*Fig 39: c2 url structure*

![](https://github.com/C1rcu1tGh0st/C1rcu1tGh0st.github.io/blob/main/assets/ss/smokeloader/stage3/6.png)
*Fig 40: encrypted c2 url data alignment*

following script can be used to get the config

```python

import struct
from arc4 import ARC4

s3 = open('stage3.bin', 'rb').read()

def rc4_decrypt(data, key):
    arc4 = ARC4(key)
    pt = arc4.decrypt(data)
    return pt

c2_struct_start = 0x284
c2_struct_end = 0x28c

for ptr in range(c2_struct_start, c2_struct_end,4):
  c2_data_address = struct.unpack('<I', s3[ptr:ptr+4])[0]
  c2_data_offset = c2_data_address - 0x10001000 
  c2_data_len = s3[c2_data_offset]
  c2_data_key = s3[c2_data_offset+1:c2_data_offset+1+4]
  c2_data = s3[c2_data_offset+1+4:c2_data_offset+1+4+c2_data_len]
  pt = rc4_decrypt(c2_data,c2_data_key)
  print(pt)


```

## C2 List
```
b'http://host-file-host6.com/'
b'http://host-host-file8.com/'

```


# References

[https://research.openanalysis.net/smoke/smokeloader/loader/config/yara/triage/2022/08/25/smokeloader.html](https://research.openanalysis.net/smoke/smokeloader/loader/config/yara/triage/2022/08/25/smokeloader.html)

[https://n1ght-w0lf.github.io/malware%20analysis/smokeloader/](https://n1ght-w0lf.github.io/malware%20analysis/smokeloader/)

[https://medium.com/@farghly.mahmod66/smoke-loader-analysis-1f1442809802](https://medium.com/@farghly.mahmod66/smoke-loader-analysis-1f1442809802)

[https://cert.pl/en/posts/2018/07/dissecting-smoke-loader/](https://cert.pl/en/posts/2018/07/dissecting-smoke-loader/)

[https://irfan-eternal.github.io/understanding-internals-of-smokeloader/](https://irfan-eternal.github.io/understanding-internals-of-smokeloader/)
