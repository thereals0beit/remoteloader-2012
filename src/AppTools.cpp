#include "stdafx.h"
#include <windows.h>
#include "AppTools.h"

CAppTools GApp;

#pragma warning( disable : 4996 )

using namespace std;

string CAppTools::GetFileExtension( string file )
{
	return GetAfterLast( file, "." );
}

string CAppTools::GetAfterLast( string haystack, string needle )
{
	return haystack.substr( haystack.find_last_of( needle ) + needle.length() );
}

string CAppTools::GetToLast( string haystack, string needle )
{
	return haystack.substr( 0, haystack.find_last_of( needle ) );
}

vector< string > CAppTools::Split_Chr( string &S, CHAR D )
{
	CHAR				SZ[2] = { D, 0 };
	
	return Split_String( S, SZ );
}

vector< string > CAppTools::Split_String( string &S, string D )
{
	string				SZ = D;
	string				SS = S;
	vector< string >	ReturnStringPool;

	size_t Found = SS.find_first_of( SZ );

	while( Found != string::npos )
	{
		if( Found > 0 )
		{
			ReturnStringPool.push_back( SS.substr( 0, Found ) );
		}

		SS = SS.substr( Found + 1 );

		Found = static_cast< int >( SS.find_first_of( SZ ) );
	}

	if( SS.length() > 0 )
	{
		ReturnStringPool.push_back( SS );
	}

	return ReturnStringPool;
}

std::string CAppTools::GetDirectoryFile( std::string File )
{
	std::string s = Directory;

	s += File;

	return s;
}

vector< string > CAppTools::GetFilesInPath( string Path )
{
	vector< string > ReturnVector;

	WIN32_FIND_DATAA WF;

	HANDLE hHandle = FindFirstFileA( Path.c_str(), &WF );

	if( hHandle != INVALID_HANDLE_VALUE )
	{
		if( _stricmp( WF.cFileName, ".." ) && _stricmp( WF.cFileName, "." ) )
		{
			ReturnVector.push_back( WF.cFileName );
		}

		while( FindNextFileA( hHandle, &WF ) == TRUE )
		{
			if( _stricmp( WF.cFileName, ".." ) && _stricmp( WF.cFileName, "." ) )
			{
				ReturnVector.push_back( WF.cFileName );
			}
		}

		FindClose( hHandle );
	}

	return ReturnVector;
}

void CAppTools::AddToLogFileA( char *szFile, char *szLog, ... )
{
#ifdef DEBUG_MESSAGES_ENABLED

	va_list va_alist;
	
	char logbuf[ 1024 ] = { 0 };
	
	FILE * fp = NULL;

	va_start( va_alist, szLog );

	_vsnprintf( logbuf + strlen( logbuf ), 
		sizeof( logbuf ) - strlen( logbuf ), 
		szLog, va_alist );

	va_end( va_alist );

	errno_t ErrorNumber = fopen_s( &fp, GetDirectoryFile( szFile ).c_str(), "a" );

	if ( ErrorNumber == 0 && fp )
	{
		fprintf_s( fp, "%s\n", logbuf );

		fclose( fp );
	}

#endif
}

void CAppTools::BaseUponModule( HMODULE hModule )
{
	char dd[ MAX_PATH ];

  	GetModuleFileNameA( hModule, dd, MAX_PATH );

	Directory = GetToLast( std::string( dd ), "\\" );

	Directory += std::string( "\\" );
}