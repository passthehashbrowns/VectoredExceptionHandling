# Vectored Exception Handling Research
This repository contains two proof-of-concepts for manipulating Windows Vectored Exception Handlers. 

Developed by Josh Magri @passthehashbrwn

## Local Vectored Exception Handler Manipulation
VEHLocal.c contains an example of adding an entry to the Vectored Exception Handler list without using the AddVectoredExceptionHandler or RtlAddVectoredExceptionHandler Windows API calls. Essentially, it is a reimplementation of the RtlAddVectoredExceptionHandler function.

## Threadless Process Injection via VEH
VEHInject.c contains an example of using Vectored Exception Handlers for threadless process injection. This works as follows:
1. Use your allocate, write, and protect primitives of choice to get shellcode in the remote process
2. Allocate space for a VEH struct in the remote process and set the handler as your shellcode
3. Get the address of the local VEH list, unprotect the .mrdata section of the remote process, and write your entry to the remote VEH list
4. Enable the IsUsingVEH bit in the remote process PEB
5. Trigger an exception in the remote process. There are many ways to do this, but this proof-of-concept spawns a suspended process and places a PAGE_GUARD trap at the process entrypoint before resuming the main thread. This will trigger an exception as soon as the process starts and pass execution to our beacon.

### Further Improvements
Anything that is missing from these examples is because it was left as an exercise for the reader. For example, the code to remove a handler has been omitted. If you feel there are any mistakes in the code, rest assured that it is an exercise.
