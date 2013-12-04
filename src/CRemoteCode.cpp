#include "stdafx.h"
#include <windows.h>
#include "CRemoteCode.h"

void CRemoteCode::RegisterDebugProc( DebugShout_t proc )
{
	for( int i = 0; i < (int)m_DebugProcList.size(); i++ )
	{
		if( m_DebugProcList[i] == proc )
			return;
	}

	m_DebugProcList.push_back( proc );
}

void CRemoteCode::PushParameter( parameter_type_t param_type, void *param )
{
	parameter_info_t pi;

	pi.ptype	= param_type;
	pi.pparam	= param;

	DebugShout( "Adding parameter to function [%i][0x%X]", pi.ptype, pi.pparam );

	m_CurrentInvokeInfo.params.push_back( pi );
}

void CRemoteCode::PushInt( int i )
{
	int *iUse = new int;

	*iUse = i;

	PushParameter( PARAMETER_TYPE_INT, iUse );
}

void CRemoteCode::PushBool( bool b )
{
	bool *bUse = new bool;

	*bUse = b;

	PushParameter( PARAMETER_TYPE_BOOL, bUse );
}

void CRemoteCode::PushShort( short s )
{
	short *sUse = new short;

	*sUse = s;

	PushParameter( PARAMETER_TYPE_SHORT, sUse );
}

void CRemoteCode::PushFloat( float f )
{
	float *fUse = new float;

	*fUse = f;

	PushParameter( PARAMETER_TYPE_FLOAT, fUse );
}

void CRemoteCode::PushByte( unsigned char uc )
{
	unsigned char *ucUse = new unsigned char;

	*ucUse = uc;

	PushParameter( PARAMETER_TYPE_BYTE, &ucUse );
}

void CRemoteCode::PushPointer( void *ptr )
{
	PushParameter( PARAMETER_TYPE_POINTER, ptr );
}

void CRemoteCode::PushANSIString( char *szString )
{
	PushParameter( PARAMETER_TYPE_STRING, szString );
}

void CRemoteCode::PushUNICODEString( wchar_t *szString )
{
	PushParameter( PARAMETER_TYPE_WSTRING, szString );
}

void CRemoteCode::PushCall( calling_convention_t cconv, FARPROC CallAddress )
{
	DebugShout( "PushCall [0x%X][0x%X]", cconv, CallAddress );

	int iFunctionBegin	= (int)m_CurrentInvokeInfo.params.size();

	m_CurrentInvokeInfo.calladdress = reinterpret_cast<unsigned long>( CallAddress );
	m_CurrentInvokeInfo.cconv		= cconv;

	switch( cconv )
	{
	case CCONV_CDECL:
		{
			DebugShout( "Entering __cdecl" );

			int iCalculateAddEsp = (iFunctionBegin * 4);

			PushAllParameters( true );

			AddByteToBuffer( 0xB8 );			//mov eax,
			AddLongToBuffer( m_CurrentInvokeInfo.calladdress );
			AddByteToBuffer( 0xFF );			//call
			AddByteToBuffer( 0xD0 );			//eax

			if( iCalculateAddEsp != 0 )
			{
				bool bUseByte = (iCalculateAddEsp <= 0xFF);

				if( bUseByte )
				{
					//add esp, [BYTE]
					AddByteToBuffer( 0x83 );
					AddByteToBuffer( 0xC4 );
					AddByteToBuffer((unsigned char)iCalculateAddEsp);
				}
				else
				{
					
					//add esp, [LONG]
					AddByteToBuffer( 0x81 );
					AddByteToBuffer( 0xC4 );
					AddLongToBuffer( iCalculateAddEsp );
				}
			}

			break;
		}
	case CCONV_STDCALL:
		{
			DebugShout( "Entering __stdcall" );

			PushAllParameters( true );

			AddByteToBuffer( 0xB8 );			//mov eax,
			AddLongToBuffer( m_CurrentInvokeInfo.calladdress );
			AddByteToBuffer( 0xFF );			//call
			AddByteToBuffer( 0xD0 );			//eax

			break;
		}
	case CCONV_THISCALL:
		{
			DebugShout( "Entering __thiscall" );

			if( iFunctionBegin == 0 ) //no params...
			{
				DebugShout( "No parameters passed for __thiscall, requires at least one parameter (ECX)" );

				break;
			}

			//first parameter of __thiscall is ALWAYS ECX. ALWAYS.
			//the parameter type should also be PARAMETER_TYPE_POINTER
			if( m_CurrentInvokeInfo.params[0].ptype != PARAMETER_TYPE_POINTER )
			{
				DebugShout( "Warning: \"THIS\" parameter type invalid [%i], should be PARAMETER_TYPE_POINTER", 
					m_CurrentInvokeInfo.params[0].ptype );
			}

			void *pThis = m_CurrentInvokeInfo.params[0].pparam;

			if( pThis == NULL )
			{
				DebugShout( "Warning: \"THIS\" parameter NULL for __thiscall function (ECX)" );
			}

			AddByteToBuffer( 0x8B );
			AddByteToBuffer( 0x0D );
			AddLongToBuffer( ( unsigned long ) pThis );

			//now we need to remove the first parameter from the vector, so when we execute the
			//parameter iteration function it is not included.....

			m_CurrentInvokeInfo.params.erase( m_CurrentInvokeInfo.params.begin() );

			PushAllParameters( true );

			AddByteToBuffer( 0xB8 );			//mov eax,
			AddLongToBuffer( m_CurrentInvokeInfo.calladdress );
			AddByteToBuffer( 0xFF );			//call
			AddByteToBuffer( 0xD0 );			//eax

			break;
		}
	case CCONV_FASTCALL:
		{
			DebugShout( "Entering __fastcall" );
			
			if( iFunctionBegin == 0 )
			{
				PushCall( CCONV_STDCALL, CallAddress );

				return;
			}
			else if( iFunctionBegin == 1 )
			{
				unsigned long ulEdxParam = *(unsigned long *)m_CurrentInvokeInfo.params[0].pparam;

				AddByteToBuffer( 0xBA );
				AddLongToBuffer( ulEdxParam );

				m_CurrentInvokeInfo.params.erase( m_CurrentInvokeInfo.params.begin() );

				PushCall( CCONV_STDCALL, CallAddress );

				return;
			}
			else
			{
				unsigned long ulEdxParam = *(unsigned long *)m_CurrentInvokeInfo.params[0].pparam;
				unsigned long ulEaxParam = *(unsigned long *)m_CurrentInvokeInfo.params[1].pparam;
				
				AddByteToBuffer( 0xBA );		//mov edx,
				AddLongToBuffer( ulEdxParam );
				AddByteToBuffer( 0xB8 );		//mov eax,
				AddLongToBuffer( ulEaxParam );

				m_CurrentInvokeInfo.params.erase( m_CurrentInvokeInfo.params.begin() );
				m_CurrentInvokeInfo.params.erase( m_CurrentInvokeInfo.params.begin() );

				PushAllParameters( true );

				AddByteToBuffer( 0xBB );		//mov ebx,
				AddLongToBuffer( m_CurrentInvokeInfo.calladdress );
				AddByteToBuffer( 0xFF );		//call
				AddByteToBuffer( 0xD3 );		//ebx
			}

			break;
		}
	}

	//clear data
	m_CurrentInvokeInfo.params.clear();
	m_CurrentInvokeInfo.calladdress = NULL;
}

remote_thread_buffer_t CRemoteCode::AssembleRemoteThreadBuffer()
{
	//xor eax, eax
	AddByteToBuffer( 0x33 );
	AddByteToBuffer( 0xC0 );

	//retn 4
	AddByteToBuffer( 0xC2 );
	AddByteToBuffer( 0x04 );
	AddByteToBuffer( 0x00 );

	return GetRemoteThreadBuffer();
}

remote_thread_buffer_t CRemoteCode::GetRemoteThreadBuffer()
{
	return m_CurrentRemoteThreadBuffer;
}

bool CRemoteCode::ExecuteRemoteThreadBuffer( remote_thread_buffer_t thread_data, bool async )
{
	unsigned char *newBuffer = new unsigned char[ thread_data.size() ];

	for( int i = 0; i < ( int ) thread_data.size(); i++ )
	{
		newBuffer[ i ] = thread_data[ i ];
	}

	void *RemoteBuffer = CommitMemory( newBuffer, thread_data.size() );

	delete[] newBuffer;

	if( RemoteBuffer == NULL )
		return false;

	HANDLE hThreadHandle = CreateRemoteThreadInProcess( ( LPTHREAD_START_ROUTINE ) RemoteBuffer, NULL );

	if( hThreadHandle == INVALID_HANDLE_VALUE )
	{
		RemoteFreeMemory( RemoteBuffer, thread_data.size() );

		DestroyRemoteThreadBuffer();

		return false;
	}

	DebugShout( "Remote Buffer Executed in process 0x%X", m_hProcess );

	if( async == true )
	{
		WaitForSingleObject( hThreadHandle, INFINITE );	
	}

	RemoteFreeMemory( RemoteBuffer, thread_data.size() );

	DestroyRemoteThreadBuffer();

	return true;
}

void CRemoteCode::DestroyRemoteThreadBuffer()
{
	for (size_t i = 0; i < m_CurrentInvokeInfo.strings.size(); i++)
	{
		RemoteFreeMemory(
			m_CurrentInvokeInfo.strings[i].ptr,
			m_CurrentInvokeInfo.strings[i].size);
	}

	m_CurrentInvokeInfo.calladdress = 0;

	m_CurrentInvokeInfo.params.clear();

	m_CurrentRemoteThreadBuffer.clear();
}

HANDLE CRemoteCode::CreateRemoteThreadInProcess( LPTHREAD_START_ROUTINE lpThread, LPVOID lpParam )
{
	return CreateRemoteThread( m_hProcess, 0, 0, lpThread, lpParam, 0, 0 );
}

void CRemoteCode::AddByteToBuffer( unsigned char in )
{
	DebugShout( "Byte opcode added to buffer: 0x%02X", in );

	m_CurrentRemoteThreadBuffer.push_back( in );
}

void CRemoteCode::AddLongToBuffer( unsigned long in )
{
	WORD LW = LOWORD( in );
	WORD HW = HIWORD( in );

	AddByteToBuffer( LOBYTE( LW ) );
	AddByteToBuffer( HIBYTE( LW ) );
	AddByteToBuffer( LOBYTE( HW ) );
	AddByteToBuffer( HIBYTE( HW ) );
}

void CRemoteCode::PushAllParameters( bool right_to_left )
{
	if( m_CurrentInvokeInfo.params.size() == 0 )
		return;

	DebugShout( "Parameters for function [%i]", m_CurrentInvokeInfo.params.size() );

	vector<parameter_info_t> currentParams = m_CurrentInvokeInfo.params;
	vector<parameter_info_t> pushOrder;

	if( right_to_left == false )
	{
		//left-to-right
		for( int i = 0; i < (int)m_CurrentInvokeInfo.params.size(); i++ )
		{
			pushOrder.push_back( m_CurrentInvokeInfo.params.at( i ) );

			DebugShout( "Parameter found [%i][%i]", i, m_CurrentInvokeInfo.params.at( i ).ptype );
		}
	}
	else
	{
		//right-to-left
		if( m_CurrentInvokeInfo.params.size() == 1 )
		{
			pushOrder.push_back( m_CurrentInvokeInfo.params.at( 0 ) );
		}
		else
		{
			int iBegin = (int)m_CurrentInvokeInfo.params.size() - 1;

			while( iBegin != -1 )
			{
				pushOrder.push_back( m_CurrentInvokeInfo.params.at( iBegin ) );

				DebugShout( "Parameter found [%i][%s]", iBegin, ParameterTypeToString( m_CurrentInvokeInfo.params.at( iBegin ).ptype ).c_str() );

				iBegin--;
			}
		}
	}

	for( int p = 0; p < (int)pushOrder.size(); p++ )
	{
		parameter_info_t *paraminfo = &pushOrder[p];

		if( paraminfo == NULL )
			continue;

		DebugShout( "Function Iter [%i]", p );
		DebugShout( "Function Parameter [%s]", ParameterTypeToString( paraminfo->ptype ).c_str() );

		if( paraminfo->pparam == NULL )
		{
			AddByteToBuffer( 0x68 );
			AddLongToBuffer( 0 );

			continue;
		}

		switch( paraminfo->ptype )
		{
			case PARAMETER_TYPE_SHORT:
			case PARAMETER_TYPE_POINTER:
			case PARAMETER_TYPE_INT:
			case PARAMETER_TYPE_FLOAT:
				{
					if( paraminfo->pparam )
					{
						unsigned long ulParam = *(unsigned long *)paraminfo->pparam;
	
						AddByteToBuffer( 0x68 );
						AddLongToBuffer( ulParam );
					}
					else
					{
						//if it is PARAMETER_TYPE_POINTER with a NULL pointer
						//we don't want to crash

						AddByteToBuffer( 0x68 );
						AddLongToBuffer( NULL );
					}

					break;
				}
			case PARAMETER_TYPE_BYTE:
				{
					unsigned char ucParam = *( unsigned char* ) paraminfo->pparam;
	
					AddByteToBuffer( 0x6A );
					AddByteToBuffer( ucParam );
	
					break;
				}
			case PARAMETER_TYPE_BOOL:
				{
					bool bParam = *( bool* ) paraminfo->pparam;
	
					unsigned char ucParam = (bParam) ? 1 : 0;
				
					AddByteToBuffer( 0x6A );
					AddByteToBuffer( ucParam );
	
					break;
				}
			case PARAMETER_TYPE_STRING:
				{
					char *szParameter = ( char* ) paraminfo->pparam;

					string_alloc_t s;

					s.size = strlen( szParameter ) + 1;
					s.ptr = CommitMemory( szParameter, s.size );

					if( s.ptr == NULL )
					{
						DebugShout( "NULL Allocated ANSI string pointer...." );

						continue; //bad beans
					}

					m_CurrentInvokeInfo.strings.push_back(s);

					AddByteToBuffer( 0x68 );
					AddLongToBuffer( ( unsigned long ) s.ptr );
	
					break;
				}
			case PARAMETER_TYPE_WSTRING:
				{
					wchar_t *szParameter = (wchar_t *)paraminfo->pparam;

					string_alloc_t s;

					s.size = ( wcslen( szParameter ) * 2 ) + 1;
					s.ptr = CommitMemory( szParameter, s.size );

					if( s.ptr == NULL )
					{
						DebugShout( "NULL Allocated UNICODE string pointer...." );

						continue; //bad beans
					}

					m_CurrentInvokeInfo.strings.push_back(s);

					AddByteToBuffer( 0x68 );
					AddLongToBuffer((unsigned long)s.ptr);
	
					break;
				}
			default:
				{
					DebugShout( "Unable to locate parameter type %i", paraminfo->ptype );
	
					break;
				}
		}
	}
}

void* CRemoteCode::CommitMemory( void *data, size_t size_of_data )
{
	void *pPointer = RemoteAllocateMemory( ( unsigned long ) size_of_data );

	if( pPointer == NULL ) return NULL;

	BOOL bWrite = WriteProcessMemory( m_hProcess, pPointer, data, size_of_data, NULL );

	if( bWrite == FALSE )
		return NULL;

	return pPointer;
}

void* CRemoteCode::RemoteAllocateMemory( size_t size )
{
	return VirtualAllocEx( m_hProcess, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
}

void CRemoteCode::RemoteFreeMemory( void *address, size_t size )
{
	VirtualFreeEx( m_hProcess, address, size, MEM_RELEASE );
}

string CRemoteCode::CallingConventionToString( calling_convention_t cconv )
{
	char *szCconvTypes[4] = 
	{
		"CCONV_CDECL",
		"CCONV_STDCALL",
		"CCONV_THISCALL",
		"CCONV_FASTCALL"
	};

	return szCconvTypes[ cconv ];
}

string CRemoteCode::ParameterTypeToString( parameter_type_t type )
{
	char *szParameterTypes[8] = 
	{
		"PARAMETER_TYPE_INT",
		"PARAMETER_TYPE_BOOL",
		"PARAMETER_TYPE_SHORT",
		"PARAMETER_TYPE_FLOAT",
		"PARAMETER_TYPE_BYTE",
		"PARAMETER_TYPE_POINTER",
		"PARAMETER_TYPE_STRING",
		"PARAMETER_TYPE_WSTRING"
	};

	return szParameterTypes[ type ];
}

void CRemoteCode::DebugShout( const char *szShout, ... )
{
#ifdef DEBUG_MESSAGES_ENABLED

	if( m_DebugProcList.size() == 0 )
		return;

	char szLogBuffer[ 1024 ] = { 0 };

	va_list va_alist;

	va_start( va_alist, szShout );

	_vsnprintf( szLogBuffer  + strlen( szLogBuffer ), sizeof( szLogBuffer ) - strlen( szLogBuffer ), szShout, va_alist );

	va_end( va_alist );

	for( int i = 0; i < (int)m_DebugProcList.size(); i++ )
	{
		DebugShout_t s = m_DebugProcList[i];

		if( s )
		{
			s( szLogBuffer );
		}
	}

#endif
}

void CRemoteCode::DebugPrintThreadToFile( string file )
{
	FILE *fp = fopen( file.c_str(), "a" );

	if( fp == NULL )
		return;

	for( int i = 0; i < (int)m_CurrentRemoteThreadBuffer.size(); i++ )
	{
		fwrite( &m_CurrentRemoteThreadBuffer[i], 1, 1, fp );
	}

	fclose( fp );
}

void CRemoteCode::DebugShoutBufferHex()
{
	string buf;

	for( int i = 0; i < (int)m_CurrentRemoteThreadBuffer.size(); i++ )
	{
		char szCurrentHex[256] = { 0 };

		sprintf( szCurrentHex, "[%02X]", m_CurrentRemoteThreadBuffer[i] );

		buf += szCurrentHex;
	}
	
	for( int i = 0; i < (int)m_DebugProcList.size(); i++ )
	{
		DebugShout_t s = m_DebugProcList[i];

		if( s )
		{
			s( ( PCHAR ) buf.c_str() );
		}
	}
}