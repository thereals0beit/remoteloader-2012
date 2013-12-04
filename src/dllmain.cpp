#include "stdafx.h"
#include <windows.h>
#include "SCDS_Utility_Module.h"

CRemoteLoader GRemoteLoader;

bool OPERATION_OK = true;
bool OPERATION_FAIL = false;

DLLEXPORT VOID DebugMsg( PCHAR S, ... )
{
	char szLogBuffer[ 1024 ] = { 0 };

	va_list va_alist;

	va_start( va_alist, S );

	_vsnprintf( szLogBuffer  + strlen( szLogBuffer ), sizeof( szLogBuffer ) - strlen( szLogBuffer ), S, va_alist );

	va_end( va_alist );

	GRemoteLoader.DebugShout( szLogBuffer );
}

VOID InternalDebugMsg( PCHAR S )
{
#ifdef DEBUG_MESSAGES_ENABLED
	GApp.AddToLogFileA( "util.log", "Shout: %s", S );
#endif
}

// API for .NET languages

DLLEXPORT BOOL WINAPI NET_RequestDebugPrivledges()
{
	return GetDebugPrivileges();
}

DLLEXPORT BOOL WINAPI NET_InjectModuleFileToMemory(HANDLE hProcess, PWCHAR File, BOOL MapPEHeader)
{
	if(hProcess == INVALID_HANDLE_VALUE) {
		GRemoteLoader.DebugShout( "[NET_InjectModuleFileToMemory] Error! Process handle is INVALID_HANDLE_VALUE, this is not possible when using NET_* API." );
		
		return FALSE;
	}

	if(File == NULL) {
		GRemoteLoader.DebugShout( "[NET_InjectModuleFileToMemory] Error! File name pointer NULL!" );

		return FALSE;
	}

	GRemoteLoader.SetProcess(hProcess);

	return (GRemoteLoader.LoadLibraryByPathIntoMemoryW(File, MapPEHeader) != NULL);
}

DLLEXPORT BOOL WINAPI NET_InjectModuleFile(HANDLE hProcess, PWCHAR File)
{
	if(hProcess == INVALID_HANDLE_VALUE) {
		GRemoteLoader.DebugShout( "[NET_InjectModuleFile] Error! Process handle is INVALID_HANDLE_VALUE, this is not possible when using NET_* API." );
		
		return FALSE;
	}

	if(File == NULL) {
		GRemoteLoader.DebugShout( "[NET_InjectModuleFile] Error! File name pointer NULL!" );

		return FALSE;
	}

	GRemoteLoader.SetProcess(hProcess);

	return (GRemoteLoader.LoadLibraryByPathW(File) != NULL);
}

DLLEXPORT void* __cdecl ProcessUtility( int Opcode, void *Parameters )
{
	GRemoteLoader.DebugShout( "[ProcessUtility] ( 0x%X, 0x%X )", Opcode, Parameters );

	switch( Opcode )
	{
	case OP_RequestDebugPrivledges:
		{
			if( GetDebugPrivileges() == TRUE )
			{
				return &OPERATION_OK;
			}

			return &OPERATION_FAIL;
		}
	case OP_InjectModuleWithByteArray:
		{
			FParams_InjectModuleWithByteArray *pParams = 
				reinterpret_cast<FParams_InjectModuleWithByteArray *>( Parameters );

			if( pParams == NULL )
			{
				return &OPERATION_FAIL;
			}

			if( pParams->BaseOfModule == NULL || pParams->SizeOfModule == 0 )
			{
				GRemoteLoader.DebugShout( "[OP_InjectModuleWithByteArray] Module Error" );

				return &OPERATION_FAIL;
			}

			if( pParams->hProcess == INVALID_HANDLE_VALUE )
			{
				GRemoteLoader.DebugShout( "[OP_InjectModuleWithByteArray] Warning! Process handle is INVALID_HANDLE_VALUE, either this is a local process or there was an error obtaining the handle.." );
			}

			GRemoteLoader.SetProcess( pParams->hProcess );

			if( GRemoteLoader.LoadLibraryFromMemory( ( PVOID ) pParams->BaseOfModule, pParams->SizeOfModule, pParams->MapPEHeader ) == NULL )
			{
				return &OPERATION_FAIL;
			}

			return &OPERATION_OK;
		}
	case OP_InjectModuleFileToMemory:
		{
			FParams_InjectModuleFileToMemory *pParams = 
				reinterpret_cast< FParams_InjectModuleFileToMemory* >( Parameters );

			if( pParams == NULL )
			{
				return &OPERATION_FAIL;
			}

			if( pParams->hProcess == INVALID_HANDLE_VALUE )
			{
				GRemoteLoader.DebugShout( "[OP_InjectModuleFileToMemory] Warning! Process handle is INVALID_HANDLE_VALUE, either this is a local process or there was an error obtaining the handle.." );
			}

			if( pParams->File == NULL )
			{
				GRemoteLoader.DebugShout( "[OP_InjectModuleFileToMemory] Error! File name pointer NULL!" );

				return &OPERATION_FAIL;
			}

			GRemoteLoader.SetProcess( pParams->hProcess );

			if( GRemoteLoader.LoadLibraryByPathIntoMemoryW( pParams->File, pParams->MapPEHeader ) )
			{
				return &OPERATION_OK;
			}

			return &OPERATION_FAIL;
		}
	case OP_InjectModuleFile:
		{
			GRemoteLoader.DebugShout( "[ProcessUtility][OP_InjectModuleFile] Called" );

			FParams_InjectModuleFile *pParams =
				reinterpret_cast<FParams_InjectModuleFile *>( Parameters );

			if( pParams == NULL )
			{
				GRemoteLoader.DebugShout( "[ProcessUtility][OP_InjectModuleFile] Parameter Failure" );

				return &OPERATION_FAIL;
			}

			if( pParams->hProcess == INVALID_HANDLE_VALUE )
			{
				GRemoteLoader.DebugShout( "[OP_InjectModuleFileToMemory] Warning! Process handle is INVALID_HANDLE_VALUE, either this is a local process or there was an error obtaining the handle.." );
			}

			if( pParams->File == NULL )
			{
				GRemoteLoader.DebugShout( "[ProcessUtility][OP_InjectModuleFile] Error! File name pointer NULL!" );

				return &OPERATION_FAIL;
			}

			GRemoteLoader.DebugShout( "[ProcessUtility][OP_InjectModuleFile] (0x%X)(%S)", pParams->hProcess, pParams->File );

			GRemoteLoader.SetProcess( pParams->hProcess );
			
			GRemoteLoader.DebugShout( "[ProcessUtility][OP_InjectModuleFile] NTLoader Process Set" );

			HMODULE hReturnModule = GRemoteLoader.LoadLibraryByPathW( pParams->File );

			if( hReturnModule )
			{
				GRemoteLoader.DebugShout( "[ProcessUtility][OP_InjectModuleFile] Success" );

				return &OPERATION_OK;
			}

			return &OPERATION_FAIL;
		}
	}

	return NULL;
}

BOOL APIENTRY DllMain( HMODULE hModule, DWORD dwReason, LPVOID lpReserved )
{
	if( dwReason == DLL_PROCESS_ATTACH )
	{
		GApp.BaseUponModule( hModule );
		GRemoteLoader.RegisterDebugProc( InternalDebugMsg );
		GRemoteLoader.DebugShout( "Module loaded: 0x%X", hModule );

		if(GetDebugPrivileges() == FALSE)
		{
			GRemoteLoader.DebugShout("WARNING: Unable to obtain Debug Privledges.");
		}
	}

    return TRUE;
}