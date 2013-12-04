#include <windows.h>

#ifdef UNICODE
#undef UNICODE
#endif

#include <Tlhelp32.h>
#include <Psapi.h>
#include <wtsapi32.h>
#include <string>

using namespace std;

#pragma comment( lib, "Advapi32.lib" )
#pragma comment( lib, "Psapi.lib" )

#define DLLEXPORT extern "C" __declspec( dllexport ) 

typedef enum {
	ARCH_X86							= 0,
	ARCH_X64							= 1,
	ARCH_XUNKNOWN						= 2
} arch_type_t;

BOOL GetDebugPrivileges( void );