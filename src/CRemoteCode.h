#include <windows.h>
#include <string>
#include <vector>
#include <fstream>
#include <algorithm>

#ifndef _CREMOTECODE_H_
#define _CREMOTECODE_H_

using namespace std;

typedef void ( __cdecl *DebugShout_t )( PCHAR S );

//these are the only types supported at the moment
typedef enum {
	CCONV_CDECL					= 0,
	CCONV_STDCALL				= 1,
	CCONV_THISCALL				= 2,
	CCONV_FASTCALL				= 3
} calling_convention_t;

//
typedef enum {
	PARAMETER_TYPE_INT			= 0,
	PARAMETER_TYPE_BOOL			= 1,
	PARAMETER_TYPE_SHORT		= 2,
	PARAMETER_TYPE_FLOAT		= 3,
	PARAMETER_TYPE_BYTE			= 4,
	PARAMETER_TYPE_POINTER		= 5,
	PARAMETER_TYPE_STRING		= 6,
	PARAMETER_TYPE_WSTRING		= 7
} parameter_type_t;

//
typedef struct {
	parameter_type_t			ptype;
	void*						pparam;
} parameter_info_t;

//
typedef struct {
	ULONG						size;
	PVOID						ptr;
} string_alloc_t;

//
typedef struct {
	calling_convention_t		cconv;
	vector<parameter_info_t>	params;
	vector<string_alloc_t>		strings;
	unsigned long				calladdress;
} invoke_info_t;

//
typedef vector< unsigned char >	remote_thread_buffer_t;
typedef vector< DebugShout_t >	debug_proc_list_t;

class CRemoteCode
{
public:

	void					SetProcess( HANDLE hProcess ){ m_hProcess = hProcess; }
	void					RegisterDebugProc( DebugShout_t proc );

	void					PushParameter( parameter_type_t param_type, void *param );
	
	void					PushInt( int i );
	void					PushBool( bool b );
	void					PushShort( short s );
	void					PushFloat( float f );
	void					PushByte( unsigned char uc );
	void					PushPointer( void *ptr );
	void					PushANSIString( char *szString );
	void					PushUNICODEString( wchar_t *szString );

	void					PushCall( calling_convention_t cconv, FARPROC CallAddress );

	remote_thread_buffer_t	AssembleRemoteThreadBuffer();
	remote_thread_buffer_t	GetRemoteThreadBuffer();

	bool					ExecuteRemoteThreadBuffer( remote_thread_buffer_t thread_data, bool async = true );

	void					DestroyRemoteThreadBuffer();

	void					DebugShoutBufferHex();
	void					DebugPrintThreadToFile( string file );

	void*					CommitMemory( void *data, size_t size_of_data );
	void*					RemoteAllocateMemory( size_t size );
	void					RemoteFreeMemory( void *address, size_t size );

	string					CallingConventionToString( calling_convention_t cconv );
	string					ParameterTypeToString( parameter_type_t type );

	HANDLE					GetProcess(){ return m_hProcess; }

	void					DebugShout( const char *szShout, ... );

protected:

	HANDLE					CreateRemoteThreadInProcess( LPTHREAD_START_ROUTINE lpThread, LPVOID lpParam );
	void					AddByteToBuffer( unsigned char in );
	void					AddLongToBuffer( unsigned long in );
	void					PushAllParameters( bool right_to_left = true );

protected:
	HANDLE					m_hProcess;
	invoke_info_t			m_CurrentInvokeInfo;
	remote_thread_buffer_t	m_CurrentRemoteThreadBuffer;
	debug_proc_list_t		m_DebugProcList;
};

#endif