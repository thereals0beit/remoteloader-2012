#include <windows.h>

#ifndef _PARAMETERS_H_
#define _PARAMETERS_H_

#define OP_RequestDebugPrivledges		1
#define OP_InjectModuleWithByteArray	2
#define OP_InjectModuleFileToMemory		3
#define OP_InjectModuleFile				4
#define OP_ClearDebugShoutList			5
#define OP_AddDebugShout				6

struct FParams_RequestDebugPrivledges
{
	// No Parameters
};

struct FParams_InjectModuleWithByteArray
{
	HANDLE		hProcess;				// Target Process
	ULONG		BaseOfModule;			// Start of buffer for module
	ULONG		SizeOfModule;			// End of buffer for module
	BOOL		MapPEHeader;			// If FALSE it does not map the PE header
};

struct FParams_InjectModuleFileToMemory
{
	HANDLE		hProcess;				// Target Process
	PWCHAR		File;					// File to map into memory (memory injection)
	BOOL		MapPEHeader;			// If FALSE it does not map the PE header
};

struct FParams_InjectModuleFile
{
	HANDLE		hProcess;				// Target Process
	PWCHAR		File;					// File to load with LoadLibraryW
};

struct FParams_AddHandler
{
	PWCHAR		File;					// Filename of API Module to load
};

struct FParams_ClearDebugShoutList
{
	// No Parameters
};

struct FParams_AddDebugShout
{
	FARPROC		Proc;					// DebugShout proc
};

#endif