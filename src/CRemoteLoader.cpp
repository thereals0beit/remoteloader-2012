#include "stdafx.h"
#include "CRemoteLoader.h"

#ifdef UNICODE
#undef UNICODE
#endif

#include <Tlhelp32.h>
#include <Psapi.h>
#include <Dbghelp.h>

#pragma comment( lib, "Psapi.lib" )
#pragma comment( lib, "dbghelp.lib" )

#define MakePtr( cast, ptr, addValue ) (cast)( (DWORD_PTR)(ptr) + (DWORD_PTR)(addValue))

#define MakeDelta(cast, x, y) (cast) ( (DWORD_PTR)(x) - (DWORD_PTR)(y))

// ######################
// ## Public functions ##
// ######################

HMODULE CRemoteLoader::LoadLibraryByPathA( PCHAR Path )
{
	WCHAR Module[ MAX_PATH ] = { 0 };

	mbstowcs( Module, Path, MAX_PATH );

	DebugShout( "[LoadLibraryByPathA] ( %S <- %s )", Module, Path );

	return LoadLibraryByPathW( Module );
}

HMODULE CRemoteLoader::LoadLibraryByPathW( PWCHAR Path )
{
	if( Path == NULL )
	{
		DebugShout( "[LoadLibraryByPathW] szString is NULL" );

		return NULL;
	}

	FARPROC RemoteLoadLibraryW = GetRemoteProcAddress( "kernel32.dll", "LoadLibraryW" );

	if( RemoteLoadLibraryW == NULL )
	{
		DebugShout( "[LoadLibraryByPathW] LoadLibraryW Resolve Failure" );

		return NULL;
	}

	DebugShout( "[LoadLibraryByPathW] LoadLibraryW = 0x%X", RemoteLoadLibraryW );

	PVOID ReturnPointerValue = RemoteAllocateMemory( sizeof( DWORD ) );

	PushUNICODEString( Path );

	PushCall( CCONV_STDCALL, RemoteLoadLibraryW );

	//mov ptr, eax
	AddByteToBuffer( 0xA3 );
	AddLongToBuffer( ( DWORD ) ReturnPointerValue );

	//xor eax, eax
	AddByteToBuffer( 0x33 );
	AddByteToBuffer( 0xC0 );

	//retn 4
	AddByteToBuffer( 0xC2 );
	AddByteToBuffer( 0x04 );
	AddByteToBuffer( 0x00 );

	if( ExecuteRemoteThreadBuffer( m_CurrentRemoteThreadBuffer, true ) == false )
	{
		DebugShout( "[LoadLibraryByPathW] ExecuteRemoteThreadBuffer failed" );

		RemoteFreeMemory( ReturnPointerValue, sizeof( DWORD ) );

		return NULL;
	}

	DebugShout( "[LoadModuleByNameW] ExecuteRemoteThreadBuffer succeeded" );

	DWORD RemoteModuleHandle = 0;

	if( ReadProcessMemory( GetProcess(), ReturnPointerValue, &RemoteModuleHandle, sizeof( DWORD ), NULL ) == TRUE )
	{
		RemoteFreeMemory( ReturnPointerValue, sizeof( DWORD ) );
	}
	else
	{
		RemoteFreeMemory( ReturnPointerValue, sizeof( DWORD ) );

		if( RemoteModuleHandle == 0 )
		{
			RemoteModuleHandle = ( DWORD ) GetRemoteModuleHandleW( Path );
		}
	}

	return ( HMODULE ) RemoteModuleHandle;
}

HMODULE CRemoteLoader::LoadLibraryByPathIntoMemoryA( PCHAR Path, BOOL PEHeader )
{
	HMODULE hReturnValue = NULL;

	DebugShout( "[LoadLibraryByPathIntoMemoryA] %s (0x%X)", Path, PEHeader );

	ModuleFile File = InitModuleFile( Path );

	if( File.IsValid() == FALSE )
	{
		DebugShout( "[LoadLibraryByPathIntoMemoryA] Failed to open file handle!" );

		return NULL;
	}

	hReturnValue = LoadLibraryFromMemory( File.Buffer, File.Size, PEHeader, Path );

	if( FreeModuleFile( File ) == FALSE )
	{
		DebugShout( "[LoadLibraryByPathIntoMemoryA] Failed to free file handle..." );
	}

	return hReturnValue;
}

HMODULE CRemoteLoader::LoadLibraryByPathIntoMemoryW( PWCHAR Path, BOOL PEHeader )
{
	CHAR PathAnsi[ MAX_PATH ] = { 0 };

	wcstombs( PathAnsi, Path, MAX_PATH );

	DebugShout( "[LoadLibraryByPathIntoMemoryW]( %S -> %s )( 0x%X )", Path, PathAnsi, PEHeader );

	return LoadLibraryByPathIntoMemoryA( PathAnsi, PEHeader );
}

HMODULE CRemoteLoader::LoadLibraryFromMemory( PVOID BaseAddress, DWORD SizeOfModule, BOOL PEHeader, PCHAR OptionalPath )
{
	DebugShout( "[LoadLibraryFromMemory] BaseAddress (0x%X) - SizeOfModule (0x%X)", BaseAddress, SizeOfModule );

	IMAGE_NT_HEADERS* ImageNtHeaders = ToNts( BaseAddress );

	if( ImageNtHeaders == NULL )
	{
		DebugShout( "[LoadLibraryFromMemory] Invalid Image: No IMAGE_NT_HEADERS" );

		return NULL;
	}

	DebugShout( "[LoadLibraryFromMemory] SizeOfImage (0x%X)", ImageNtHeaders->OptionalHeader.SizeOfImage );

	if( ImageNtHeaders->FileHeader.NumberOfSections == 0 )
	{
		DebugShout( "[LoadLibraryFromMemory] Invalid Image: No Sections" );

		return NULL;
	}

	if( ( ImageNtHeaders->OptionalHeader.ImageBase % 4096 ) != 0 )
	{
		DebugShout( "[LoadLibraryFromMemory] Invalid Image: Not Page Aligned" );
		
		return NULL;
	}

	if( ImageNtHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR ].Size )
	{
		if( ImageDirectoryEntryToData( BaseAddress, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR ) )
		{
			DebugShout( "[LoadLibraryFromMemory] This method is not supported for Managed executables!" );

			return NULL;
		}
	}

	DebugShout( "[LoadLibraryFromMemory] No COM/CLR data found!" );

	// SizeOfImage NOT the same as module size MOTHERFUCKER
	// http://www.youtube.com/watch?v=pele5vptVgc

	PVOID AllocatedRemoteMemory = RemoteAllocateMemory( ImageNtHeaders->OptionalHeader.SizeOfImage );

	if( AllocatedRemoteMemory == NULL )
	{
		DebugShout( "[LoadLibraryFromMemory] Failed to allocate remote memory for module!" );

		return NULL;
	}

	DebugShout( "[LoadLibraryFromMemory] Allocated remote module at [0x%X]!", AllocatedRemoteMemory );

	if( ProcessImportTable( BaseAddress, AllocatedRemoteMemory, OptionalPath ) == FALSE )
	{
		DebugShout( "[LoadLibraryFromMemory] Failed to fix imports!" );

		return NULL;
	}

	DebugShout( "[LoadLibraryFromMemory] Fixed Imports!" );

	if( ProcessRelocations( BaseAddress, AllocatedRemoteMemory ) == FALSE )
	{
		DebugShout( "[LoadLibraryFromMemory] Failed to process relocations!" );

		RemoteFreeMemory( AllocatedRemoteMemory, SizeOfModule );

		return NULL;
	}

	DebugShout( "[LoadLibraryFromMemory] Fixed Relocations!" );

	if( ProcessSections( BaseAddress, AllocatedRemoteMemory, PEHeader ) == FALSE )
	{
		DebugShout( "[LoadLibraryFromMemory] Failed to process sections!" );
	}

	DebugShout( "[LoadLibraryFromMemory] Processed sections!" );

	if( ProcessTlsEntries( BaseAddress, AllocatedRemoteMemory ) == FALSE )
	{
		DebugShout( "[LoadModuleFromMemory] ProcessTlsEntries Failed!" );

		// we can also choose to continue here..

		return NULL;
	}

	DebugShout( "[LoadModuleFromMemory] Processed Tls Entries!" );

	if( ImageNtHeaders->OptionalHeader.AddressOfEntryPoint )
	{
		FARPROC DllEntryPoint = MakePtr( FARPROC, AllocatedRemoteMemory, ImageNtHeaders->OptionalHeader.AddressOfEntryPoint );

		DebugShout( "[LoadModuleFromMemory] DllEntrypoint = 0x%X", DllEntryPoint );

		if( CallEntryPoint( AllocatedRemoteMemory, DllEntryPoint ) == false )
		{
			DebugShout( "[LoadModuleFromMemory] Failed to execute remote thread buffer" );
		}
		else
		{
			DebugShout( "[LoadModuleFromMemory] Executed the remote thread buffer successfully [0x%X]", DllEntryPoint );
		}
	}
	else
	{
		DebugShout( "[LoadModuleFromMemory] AddressOfEntryPoint is NULL" );
	}

	DebugShout( "[LoadModuleFromMemory] Returning Pointer (0x%X)", AllocatedRemoteMemory );

	return ( HMODULE ) AllocatedRemoteMemory;
}

// #######################
// ## Private functions ##
// #######################

HMODULE CRemoteLoader::GetRemoteModuleHandleA( PCHAR Module )
{
	HANDLE tlh = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, GetProcessId( GetProcess() ) );

	MODULEENTRY32 modEntry;
	
	modEntry.dwSize = sizeof( MODULEENTRY32 );

	Module32First( tlh, &modEntry );
	do
	{
		if( _stricmp( Module, modEntry.szModule ) == 0 )
		{
			CloseHandle( tlh );

			return modEntry.hModule;
		}
	}
	while( Module32Next( tlh, &modEntry ) );

	CloseHandle( tlh );

	return NULL;
}

HMODULE CRemoteLoader::GetRemoteModuleHandleW( PWCHAR Module )
{
	CHAR ModuleAnsi[ MAX_PATH ] = { 0 };

	wcstombs( ModuleAnsi, Module, MAX_PATH );

	return GetRemoteModuleHandleA( ModuleAnsi );
}

FARPROC CRemoteLoader::GetRemoteProcAddress( PCHAR Module, PCHAR Function )
{
	HMODULE hKernel32 = LoadLibraryA( "Kernel32.dll" );

	if( hKernel32 == NULL ) return NULL;

	DWORD GetProcAddressOffset = ( DWORD ) GetProcAddress - ( DWORD ) hKernel32;

	HMODULE hRemoteKernel32 = GetRemoteModuleHandleA( "Kernel32.dll" );

	if( hRemoteKernel32 == NULL ) return NULL;
	
	HMODULE hRemoteModule = GetRemoteModuleHandleA( Module );

	if( hRemoteModule == NULL ) return NULL;
	
	PVOID ReturnPointerValue = RemoteAllocateMemory( sizeof( DWORD ) );

	PushInt( ( INT ) hRemoteModule );
	PushANSIString( ( PCHAR ) Function );
	PushCall( CCONV_STDCALL, ( FARPROC )( ( DWORD_PTR ) hRemoteKernel32 + ( DWORD_PTR ) GetProcAddressOffset ) );

	//mov ptr, eax
	AddByteToBuffer( 0xA3 );
	AddLongToBuffer( ( DWORD ) ReturnPointerValue );

	//xor eax, eax
	AddByteToBuffer( 0x33 );
	AddByteToBuffer( 0xC0 );

	//retn 4
	AddByteToBuffer( 0xC2 );
	AddByteToBuffer( 0x04 );
	AddByteToBuffer( 0x00 );

	if( ExecuteRemoteThreadBuffer( m_CurrentRemoteThreadBuffer, true ) == false )
	{
		RemoteFreeMemory( ReturnPointerValue, sizeof( DWORD ) );

		return NULL;
	}

	DWORD ProcAddressRemote = 0;

	if( ReadProcessMemory( GetProcess(), ReturnPointerValue, &ProcAddressRemote, sizeof( DWORD ), NULL ) == TRUE )
	{
		RemoteFreeMemory( ReturnPointerValue, sizeof( DWORD ) );

		return ( FARPROC ) ProcAddressRemote;
	}
	
	RemoteFreeMemory( ReturnPointerValue, sizeof( DWORD ) );

	return NULL;
}

FARPROC CRemoteLoader::GetRemoteProcAddress( PCHAR Module, SHORT Function )
{
	HMODULE hKernel32 = LoadLibraryA( "Kernel32.dll" );

	if( hKernel32 == NULL ) return NULL;

	DWORD GetProcAddressOffset = ( DWORD ) GetProcAddress - ( DWORD ) hKernel32;

	HMODULE hRemoteKernel32 = GetRemoteModuleHandleA( "Kernel32.dll" );

	if( hRemoteKernel32 == NULL ) return NULL;
	
	HMODULE hRemoteModule = GetRemoteModuleHandleA( Module );

	if( hRemoteModule == NULL ) return NULL;
	
	PVOID ReturnPointerValue = RemoteAllocateMemory( sizeof( DWORD ) );

	PushInt( ( INT ) hRemoteModule ); // HACKHACK: Why is this an int?
	PushInt( ( INT ) Function );
	PushCall( CCONV_STDCALL, ( FARPROC )( ( DWORD_PTR ) hRemoteKernel32 + ( DWORD_PTR ) GetProcAddressOffset ) );

	//mov ptr, eax
	AddByteToBuffer( 0xA3 );
	AddLongToBuffer( ( DWORD ) ReturnPointerValue );

	//xor eax, eax
	AddByteToBuffer( 0x33 );
	AddByteToBuffer( 0xC0 );

	//retn 4
	AddByteToBuffer( 0xC2 );
	AddByteToBuffer( 0x04 );
	AddByteToBuffer( 0x00 );

	if( ExecuteRemoteThreadBuffer( m_CurrentRemoteThreadBuffer, true ) == false )
	{
		RemoteFreeMemory( ReturnPointerValue, sizeof( DWORD ) );

		return NULL;
	}

	DWORD ProcAddressRemote = 0;

	if( ReadProcessMemory( GetProcess(), ReturnPointerValue, &ProcAddressRemote, sizeof( DWORD ), NULL ) == TRUE )
	{
		RemoteFreeMemory( ReturnPointerValue, sizeof( DWORD ) );

		return ( FARPROC ) ProcAddressRemote;
	}
	
	RemoteFreeMemory( ReturnPointerValue, sizeof( DWORD ) );

	return NULL;
}

IMAGE_DOS_HEADER* CRemoteLoader::ToDos( PVOID BaseAddress )
{
	IMAGE_DOS_HEADER* ImageDosHeader = reinterpret_cast< IMAGE_DOS_HEADER* >( BaseAddress );

	if( !ImageDosHeader )
		return NULL;

	if( ImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE )
		return NULL;

	return ImageDosHeader;
}

IMAGE_NT_HEADERS* CRemoteLoader::ToNts( PVOID BaseAddress )
{
	IMAGE_DOS_HEADER* ImageDosHeader = ToDos( BaseAddress );

	if( ImageDosHeader == NULL )
		return NULL;

	IMAGE_NT_HEADERS* ImageNtHeaders = 
		reinterpret_cast< IMAGE_NT_HEADERS* >( reinterpret_cast< DWORD >( BaseAddress ) + ImageDosHeader->e_lfanew );

	if( ImageNtHeaders->Signature != IMAGE_NT_SIGNATURE )
		return NULL;

	return ImageNtHeaders;
}

PVOID CRemoteLoader::RvaToPointer( DWORD RVA, PVOID BaseAddress )
{
	PIMAGE_NT_HEADERS ImageNtHeaders = ToNts( BaseAddress );

	if( ImageNtHeaders == NULL ) 
		return NULL;

	return ::ImageRvaToVa( ImageNtHeaders, BaseAddress, RVA, NULL );
}

PVOID CRemoteLoader::ImageDirectoryEntryToData( PVOID BaseAddress, USHORT DataDirectory )
{
	ULONG Size = 0;

	return ::ImageDirectoryEntryToData( BaseAddress, TRUE, DataDirectory, &Size );
}

BOOL CRemoteLoader::CallEntryPoint( PVOID BaseAddress, FARPROC Entrypoint )
{
	PushInt( ( INT ) BaseAddress );
	PushInt( DLL_PROCESS_ATTACH );
	PushInt( 0 );
	PushCall( CCONV_STDCALL, Entrypoint );

	return ExecuteRemoteThreadBuffer( AssembleRemoteThreadBuffer() );
}

BOOL CRemoteLoader::ProcessImportTable( PVOID BaseAddress, PVOID RemoteAddress, PCHAR OptionalPath )
{
	IMAGE_NT_HEADERS* ImageNtHeaders = ToNts( BaseAddress );

	if( ImageNtHeaders == NULL )
		return FALSE;

	if( ImageNtHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].Size )
	{
		IMAGE_IMPORT_DESCRIPTOR* ImageImportDescriptor = ( IMAGE_IMPORT_DESCRIPTOR* )
			RvaToPointer( ImageNtHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress, BaseAddress );

		if( ImageImportDescriptor )
		{
			for( ; ImageImportDescriptor->Name; ImageImportDescriptor++ )
			{
				PCHAR ModuleName = ( PCHAR ) RvaToPointer( ImageImportDescriptor->Name, BaseAddress );

				if( ModuleName == NULL )
				{
					DebugShout( "[ProcessImportTable] Module name for entry NULL" );

					continue;
				}

				DebugShout( "[ProcessImportTable] Module Name [%s]", ModuleName );

				HMODULE ModuleBase = GetRemoteModuleHandleA( ModuleName );

				if( ModuleBase == NULL )
				{
					ModuleBase = LoadLibraryByPathA( ModuleName );
				}

				if( ModuleBase == NULL )
				{
					DebugShout( "[ProcessImportTable] Failed to obtain module handle [%s]", ModuleName );

					continue;
				}

				IMAGE_THUNK_DATA *ImageThunkData	= NULL;
				IMAGE_THUNK_DATA *ImageFuncData		= NULL;

				if( ImageImportDescriptor->OriginalFirstThunk )
				{
					ImageThunkData	= ( IMAGE_THUNK_DATA* ) RvaToPointer( ImageImportDescriptor->OriginalFirstThunk, BaseAddress );
					ImageFuncData	= ( IMAGE_THUNK_DATA* ) RvaToPointer( ImageImportDescriptor->FirstThunk, BaseAddress );
				}
				else
				{
					ImageThunkData	= ( IMAGE_THUNK_DATA* ) RvaToPointer( ImageImportDescriptor->FirstThunk, BaseAddress );
					ImageFuncData	= ( IMAGE_THUNK_DATA* ) RvaToPointer( ImageImportDescriptor->FirstThunk, BaseAddress );
				}

				
				if( ImageThunkData == NULL )
				{
					DebugShout( "[ProcessImportTable] Image Thunk Data is NULL" );
				}

				if( ImageFuncData == NULL )
				{
					DebugShout( "[ProcessImportTable] Image Func Data is NULL" );
				}

				for( ; ImageThunkData->u1.AddressOfData; ImageThunkData++, ImageFuncData++ )
				{
					FARPROC FunctionAddress = NULL;

					if( IMAGE_SNAP_BY_ORDINAL( ImageThunkData->u1.Ordinal ) )
					{
						SHORT Ordinal = ( SHORT ) IMAGE_ORDINAL( ImageThunkData->u1.Ordinal );

						FunctionAddress = ( FARPROC ) GetRemoteProcAddress( ModuleName, Ordinal );

						DebugShout( "[ProcessImportTable] Processed (%s -> %i) -> (0x%X)", 
							ModuleName, Ordinal, FunctionAddress );

						if( this->GetProcess() == INVALID_HANDLE_VALUE )
						{
							DebugShout( "[ProcessImportTable] Normal Value (0x%X)",
								GetProcAddress( GetModuleHandleA( ModuleName ), ( LPCSTR ) Ordinal ) );
						}
					}
					else
					{
						IMAGE_IMPORT_BY_NAME* ImageImportByName = ( IMAGE_IMPORT_BY_NAME* )
							RvaToPointer( *( DWORD* ) ImageThunkData, BaseAddress );

						PCHAR NameOfImport = ( PCHAR ) ImageImportByName->Name;

						FunctionAddress = ( FARPROC ) GetRemoteProcAddress( ModuleName, NameOfImport );

						DebugShout( "[ProcessImportTable] Processed (%s -> %s) -> (0x%X)", 
							ModuleName, NameOfImport, FunctionAddress );

						if( this->GetProcess() == INVALID_HANDLE_VALUE )
						{
							DebugShout( "[ProcessImportTable] Normal Value (0x%X)",
								GetProcAddress( GetModuleHandleA( ModuleName ), NameOfImport ) );
						}
					}

					ImageFuncData->u1.Function = ( DWORD ) FunctionAddress;
				}
			}

			return TRUE;
		}
		else
		{
			DebugShout( "[ProcessImportTable] Size of table confirmed but pointer to data invalid!" );

			return FALSE;
		}
	}
	else
	{
		DebugShout( "[ProcessImportTable] No Imports" );

		return TRUE;
	}

	return FALSE;
}

BOOL CRemoteLoader::ProcessRelocation( INT ImageBaseDelta, WORD Data, PBYTE RelocationBase )
{
	BOOL bReturn = TRUE;

	switch( IMR_RELTYPE( Data ) )
	{
	case IMAGE_REL_BASED_ABSOLUTE:
		{
			DebugShout( "[ProcessRelocation] IMAGE_REL_BASED_ABSOLUTE" );

			break;
		}
	case IMAGE_REL_BASED_HIGH:
		{
			SHORT* Raw		= reinterpret_cast< SHORT* >( RelocationBase + IMR_RELOFFSET( Data ) );
			SHORT Backup	= *Raw;

			*Raw += HIWORD( ImageBaseDelta );

			DebugShout( "[ProcessRelocation] IMAGE_REL_BASED_HIGH (0x%X) -> (0x%X)", 
				Backup, *Raw );

			break;
		}
	case IMAGE_REL_BASED_LOW:
		{
			SHORT* Raw		= reinterpret_cast< SHORT* >( RelocationBase + IMR_RELOFFSET( Data ) );
			SHORT Backup	= *Raw;

			*Raw += LOWORD( ImageBaseDelta );

			DebugShout( "[ProcessRelocation] IMAGE_REL_BASED_LOW (0x%X) -> (0x%X)", 
				Backup, *Raw );

			break;
		}
	case IMAGE_REL_BASED_HIGHLOW:
		{
			DWORD32* Raw	= reinterpret_cast< DWORD32* >( RelocationBase + IMR_RELOFFSET( Data ) );
			DWORD32 Backup	= *Raw;

			*Raw += ImageBaseDelta;

			DebugShout( "[ProcessRelocation] IMAGE_REL_BASED_HIGHLOW (0x%X) -> (0x%X)", 
				Backup, *Raw );

			break;
		}
	case IMAGE_REL_BASED_DIR64:
		{
			DWORD64* Raw	= reinterpret_cast< DWORD64* >( RelocationBase + IMR_RELOFFSET( Data ) );
			DWORD64 Backup	= *Raw;

			*Raw += ImageBaseDelta;

			DebugShout( "[ProcessRelocation] IMAGE_REL_BASED_DIR64 (0x%X) -> (0x%X)", 
				Backup, *Raw );

			break;
		}
	case IMAGE_REL_BASED_HIGHADJ:
		{
			DebugShout( "[ProcessRelocation] IMAGE_REL_BASED_HIGHADJ" );

			break;
		}
	default:
		{
			DebugShout( "[ProcessRelocation] UNKNOWN RELOCATION (0x%X)", IMR_RELTYPE( Data ) );

			bReturn = FALSE;

			break;
		}
	}

	return bReturn;
}

BOOL CRemoteLoader::ProcessRelocations( PVOID BaseAddress, PVOID RemoteAddress )
{
	IMAGE_NT_HEADERS* ImageNtHeaders = ToNts( BaseAddress );

	if( ImageNtHeaders == NULL )
		return FALSE;

	if( ImageNtHeaders->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED )
	{
		DebugShout( "[ProcessRelocations] Relocations have been stripped from this executable, continuing.." );

		return TRUE;
	}
	else
	{
		DWORD ImageBaseDelta = MakeDelta( DWORD, RemoteAddress, ImageNtHeaders->OptionalHeader.ImageBase );

		DebugShout( "[ProcessRelocations] VirtualAddress (0x%X)",
			ImageNtHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ].VirtualAddress );

		DWORD RelocationSize = ImageNtHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ].Size;

		DebugShout( "[ProcessRelocations] Relocation Size [0x%X]", RelocationSize );

		if( RelocationSize )
		{
			IMAGE_BASE_RELOCATION* RelocationDirectory = ( IMAGE_BASE_RELOCATION* ) 
				RvaToPointer( ImageNtHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ].VirtualAddress, BaseAddress );

			if( RelocationDirectory )
			{
				DebugShout( "[ProcessRelocations] RelocationDirectory (0x%X)", RelocationDirectory );

				PVOID RelocationEnd = reinterpret_cast< PBYTE >( RelocationDirectory ) + RelocationSize;

				while( RelocationDirectory < RelocationEnd )
				{
					PBYTE RelocBase = static_cast< PBYTE >( RvaToPointer( RelocationDirectory->VirtualAddress, BaseAddress ) );

					DWORD NumRelocs = ( RelocationDirectory->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION ) ) / sizeof( WORD ); 

					PWORD RelocationData = reinterpret_cast< PWORD >( RelocationDirectory + 1 );

					DebugShout( "[ProcessRelocations] RelocationDirectory (0x%X)", RelocationDirectory );
					DebugShout( "[ProcessRelocations] RelocationData (0x%X)", RelocationData );

					 for( DWORD i = 0; i < NumRelocs; ++i, ++RelocationData )
					 {
						 if( ProcessRelocation( ImageBaseDelta, *RelocationData, RelocBase ) == FALSE )
						 {
							 DebugShout( "[ProcessRelocations] Unable to process relocation (%i)", i );
						 }
					 }

					RelocationDirectory = reinterpret_cast< PIMAGE_BASE_RELOCATION >( RelocationData );
				}
			}
			else
			{
				DebugShout( "[ProcessRelocations] Relocations have a size, but the pointer is invalid" );

				return FALSE;
			}
		}
		else
		{
			DebugShout( "[ProcessRelocations] Relocations have have not been found in this executable, continuing.." );

			return TRUE;
		}
	}

	return TRUE;
}

BOOL CRemoteLoader::ProcessTlsEntries( PVOID BaseAddress, PVOID RemoteAddress )
{
	IMAGE_NT_HEADERS* ImageNtHeaders = ToNts( BaseAddress );

	if( ImageNtHeaders == NULL ) 
		return FALSE;

	if( ImageNtHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_TLS ].Size == 0 )
		return TRUE; // Success when there is no Tls Entries

	DebugShout( "[ProcessTlsEntries] Tls Data detected!" );

	IMAGE_TLS_DIRECTORY* TlsDirectory =
		( IMAGE_TLS_DIRECTORY* ) RvaToPointer( ImageNtHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_TLS ].VirtualAddress, BaseAddress );

	if( TlsDirectory == NULL )
		return TRUE; // Success when there is no Tls entries / broken data?

	DebugShout( "[ProcessTlsEntries] TlsDirectory (0x%X)", 
		TlsDirectory );

	if( TlsDirectory->AddressOfCallBacks == NULL )
		return TRUE; // Success when there is no Tls entries / broken data?

	DebugShout( "[ProcessTlsEntries] TlsDirectory->AddressOfCallBacks (0x%X)", 
		TlsDirectory->AddressOfCallBacks );

	PIMAGE_TLS_CALLBACK TLSCallbacks[ 0xFF ];

	if( ReadProcessMemory( GetProcess(), ( LPCVOID ) TlsDirectory->AddressOfCallBacks, TLSCallbacks, sizeof( TLSCallbacks ), NULL ) == FALSE )
	{
		DebugShout( "[ProcessTlsEntries] Failed ReadProcessMemory" );

		return FALSE;
	}

	BOOL SuccessValue = TRUE;

	for( int i = 0; TLSCallbacks[i]; i++ )
	{
		DebugShout( "[ProcessTlsEntries] TLSCallbacks[%i] = 0x%X (0x%X)", i, TLSCallbacks[i], RemoteAddress );

		// As a consequence of the relocation stuff mentioned above, pCallbacks[i] is already fixed

		if( CallEntryPoint( RemoteAddress, ( FARPROC ) TLSCallbacks[i] ) == false )
		{
			DebugShout( "[ProcessTlsEntries] Failed to execute Tls Entry [%i]", i );
		}
		else
		{
			DebugShout( "[ProcessTlsEntries] Called Tls Callback (0x%X)", TLSCallbacks[i] );
		}
	}

	return SuccessValue;
}

ULONG CRemoteLoader::GetSectionProtection( ULONG Characteristics )
{
	DWORD Result = 0;

	if( Characteristics & IMAGE_SCN_MEM_NOT_CACHED )
	{
		Result |= PAGE_NOCACHE;
	}

	if( Characteristics & IMAGE_SCN_MEM_EXECUTE )
	{
		if( Characteristics & IMAGE_SCN_MEM_READ )
		{
			if( Characteristics & IMAGE_SCN_MEM_WRITE )
			{
				Result |= PAGE_EXECUTE_READWRITE;
			}
			else
			{
				Result |= PAGE_EXECUTE_READ;
			}
		}
		else if( Characteristics & IMAGE_SCN_MEM_WRITE )
		{
			Result |= PAGE_EXECUTE_WRITECOPY;
		}
		else
		{
			Result |= PAGE_EXECUTE;
		}
	}
	else if( Characteristics & IMAGE_SCN_MEM_READ )
	{
		if( Characteristics & IMAGE_SCN_MEM_WRITE )
		{
			Result |= PAGE_READWRITE;
		}
		else
		{
			Result |= PAGE_READONLY;
		}
	}
	else if( Characteristics & IMAGE_SCN_MEM_WRITE )
	{
		Result |= PAGE_WRITECOPY;
	}
	else
	{
		Result |= PAGE_NOACCESS;
	}

	return Result;
}

BOOL CRemoteLoader::ProcessSection( BYTE* Name, PVOID BaseAddress, PVOID RemoteAddress, ULONG RawData, ULONG VirtualAddress, ULONG RawSize, ULONG VirtualSize, ULONG ProtectFlag )
{
	DebugShout( "[ProcessSection] ProcessSection( %s, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X )",
		Name, BaseAddress, RemoteAddress, RawData, VirtualAddress, RawSize, VirtualSize, ProtectFlag );

	HANDLE hProcess = GetProcess();

	if( hProcess == INVALID_HANDLE_VALUE )
	{
		hProcess = GetCurrentProcess();
	}

	if( WriteProcessMemory( hProcess,
		MakePtr( PVOID, RemoteAddress, VirtualAddress ),
		MakePtr( PVOID, BaseAddress, RawData ),
		RawSize,
		NULL ) == FALSE )
	{
		DebugShout( "[ProcessSection] Failed to write memory for (%s) -> (%s)", Name, LastErrorString() );

		return FALSE;
	}

	DWORD dwOldProtect = NULL;

	if( VirtualProtectEx( hProcess,
		MakePtr( PVOID, RemoteAddress, VirtualAddress ),
		VirtualSize,
		ProtectFlag,
		&dwOldProtect ) == FALSE )
	{
		DebugShout( "[ProcessSection] Failed to protect memory for (%s) -> (%s)", Name, LastErrorString() );

		return FALSE;
	}

	return TRUE;
}

BOOL CRemoteLoader::ProcessSections( PVOID BaseAddress, PVOID RemoteAddress, BOOL MapPEHeader )
{
	IMAGE_NT_HEADERS* ImageNtHeaders = ToNts( BaseAddress );

	if( ImageNtHeaders == NULL ) 
		return FALSE;

	// Write PE header

	if( MapPEHeader )
	{
		if( WriteProcessMemory( GetProcess(), RemoteAddress, BaseAddress, ImageNtHeaders->OptionalHeader.SizeOfHeaders, NULL ) == FALSE )
		{
			DebugShout( "[ProcessSections] Failed to map PE header!" );
		}
		else
		{
			DebugShout( "[ProcessSections] Mapped PE Header successfully!" );
		}
	}
	else
	{
		DebugShout( "[ProcessSections] PE Header mapping disabled, skipping." );
	}

	// Write individual sections

	PIMAGE_SECTION_HEADER ImageSectionHeader = ( PIMAGE_SECTION_HEADER )
		( ( ( ULONG_PTR ) &ImageNtHeaders->OptionalHeader ) + ImageNtHeaders->FileHeader.SizeOfOptionalHeader );

	for( DWORD i = 0; i < ImageNtHeaders->FileHeader.NumberOfSections; i++ )
	{
		ULONG Protection = GetSectionProtection( ImageSectionHeader[ i ].Characteristics );

		if( !_stricmp( ".reloc", ( CHAR* ) ImageSectionHeader[ i ].Name ) )
		{
			DebugShout( "[ProcessSections] Skipping \".reloc\" section." );

			continue; // NOPE
		}

		if( ProcessSection( 
			ImageSectionHeader[ i ].Name,
			BaseAddress,
			RemoteAddress,
			ImageSectionHeader[ i ].PointerToRawData,
			ImageSectionHeader[ i ].VirtualAddress,
			ImageSectionHeader[ i ].SizeOfRawData,
			ImageSectionHeader[ i ].Misc.VirtualSize,
			Protection ) == FALSE )
		{
			DebugShout( "[ProcessSections] Failed %s", ImageSectionHeader[ i ].Name );
		}
		else
		{
			DebugShout( "[ProcessSections] Success %s", ImageSectionHeader[ i ].Name );
		}
	}

	return TRUE;
}

// #######################
// ## Private functions ##
// #######################

ModuleFile CRemoteLoader::InitModuleFile( PCHAR FileName )
{
	ModuleFile r;

	r.Buffer	= 0;
	r.Size		= 0;

	HANDLE hFile = CreateFileA(
		FileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );

	if( hFile == INVALID_HANDLE_VALUE )
	{
		DebugShout( "[InitModuleFile] CreateFileA Failed" );

		return r;
	}

	DebugShout( "[InitModuleFile] File opened" );

	if( GetFileAttributesA( FileName ) & FILE_ATTRIBUTE_COMPRESSED )
	{
		r.Size = GetCompressedFileSizeA( FileName, NULL );

		DebugShout( "[InitModuleFile] File is compressed!" );
	}
	else
	{
		r.Size = GetFileSize( hFile, NULL );
	}

	DebugShout( "[InitModuleFile] Size [0x%X]", r.Size );

	if( r.Size == 0 )
	{
		CloseHandle( hFile );

		return r;
	}

	unsigned char *AllocatedFile = ( unsigned char* ) VirtualAlloc( NULL, r.Size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );

	if( AllocatedFile == NULL )
	{
		DebugShout( "[InitModuleFile] Failed to allocate buffer!" );

		r.Size = 0;

		CloseHandle( hFile );

		return r;
	}

	DebugShout( "[InitModuleFile] Buffer allocated" );

	DWORD NumberOfBytesRead = 0;

	if( ReadFile( hFile, AllocatedFile, r.Size, &NumberOfBytesRead, FALSE ) == FALSE )
	{
		DebugShout( "[InitModuleFile] Read file failed.." );

		r.Buffer	= 0;
		r.Size		= 0;
	}
	else
	{
		DebugShout( "[InitModuleFile] Read file complete (0x%X)", NumberOfBytesRead );

		r.Buffer = AllocatedFile;
	}

	DebugShout( "[InitModuleFile] Buffer [0x%X]", r.Buffer );

	CloseHandle( hFile );

	return r;
}

BOOL CRemoteLoader::FreeModuleFile( ModuleFile Handle )
{
	if( Handle.Buffer )
	{
		VirtualFree( Handle.Buffer, Handle.Size, MEM_RELEASE );

		Handle.Buffer = 0;
	}

	Handle.Size = 0;

	return ( Handle.Buffer == 0 && Handle.Size == 0 );
}

TCHAR* CRemoteLoader::LastErrorString()
{
	TCHAR* returnBuffer = 0;

	FormatMessage( 
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, 
		NULL, 
		GetLastError(), 
		MAKELANGID( LANG_NEUTRAL, SUBLANG_DEFAULT ), 
		( LPTSTR ) &returnBuffer ,
		0,
		NULL );

	return returnBuffer;
}