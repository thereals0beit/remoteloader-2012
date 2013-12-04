#ifndef _CREMOTELOAD_H_
#define _CREMOTELOAD_H_

#ifndef IMR_RELTYPE
#define IMR_RELTYPE(x)				((x >> 12) & 0xF)
#endif

#ifndef IMR_RELOFFSET
#define IMR_RELOFFSET(x)			(x & 0xFFF)
#endif

struct ModuleFile
{
	PVOID							Buffer;
	INT								Size;

	BOOL IsValid()
	{
		return ( Buffer && Size );
	}
};

class CRemoteLoader : public CRemoteCode
{
public:

	class CAdditionalData
	{
	public:
		VOID* Data;
		ULONG Size;
	};

	HMODULE							LoadLibraryByPathA( PCHAR Path );
	HMODULE							LoadLibraryByPathW( PWCHAR Path );
	HMODULE							LoadLibraryByPathIntoMemoryA( PCHAR Path, BOOL PEHeader );
	HMODULE							LoadLibraryByPathIntoMemoryW(  PWCHAR Path, BOOL PEHeader );
	HMODULE							LoadLibraryFromMemory( PVOID BaseAddress, DWORD SizeOfModule, BOOL PEHeader, PCHAR OptionalPath = 0 );

private:

	HMODULE							GetRemoteModuleHandleA( PCHAR Module );
	HMODULE							GetRemoteModuleHandleW( PWCHAR Module );
	FARPROC							GetRemoteProcAddress( PCHAR Module, PCHAR Function );
	FARPROC							GetRemoteProcAddress( PCHAR Module, SHORT Function );

protected:

	IMAGE_DOS_HEADER*				ToDos( PVOID BaseAddress );
	IMAGE_NT_HEADERS*				ToNts( PVOID BaseAddress );
	PVOID							RvaToPointer( DWORD RVA, PVOID BaseAddress );
	PVOID							ImageDirectoryEntryToData( PVOID BaseAddress, USHORT DataDirectory );
	BOOL							CallEntryPoint( PVOID BaseAddress, FARPROC Entrypoint );

	BOOL							ProcessImportTable( PVOID BaseAddress, PVOID RemoteAddress, PCHAR OptionalPath );
	BOOL							ProcessRelocation( INT ImageBaseDelta, WORD Data, PBYTE RelocationBase );
	BOOL							ProcessRelocations( PVOID BaseAddress, PVOID RemoteAddress );
	BOOL							ProcessTlsEntries( PVOID BaseAddress, PVOID RemoteAddress );
	ULONG							GetSectionProtection( ULONG Characteristics );
	BOOL							ProcessSection( BYTE* Name, PVOID BaseAddress, PVOID RemoteAddress, ULONG RawData, ULONG VirtualAddress, ULONG RawSize, ULONG VirtualSize, ULONG ProtectFlag );
	BOOL							ProcessSections( PVOID BaseAddress, PVOID RemoteAddress, BOOL MapPEHeader );

private:

	ModuleFile						InitModuleFile( PCHAR FileName );
	BOOL							FreeModuleFile( ModuleFile Handle );
	TCHAR*							LastErrorString();
};



#endif