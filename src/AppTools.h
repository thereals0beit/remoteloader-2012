#ifndef __APPTOOLS_HEADER__
#define __APPTOOLS_HEADER__

#include <windows.h>
#include <string>
#include <vector>

class CAppTools
{
public:
	std::string					GetFileExtension( std::string file );
	std::string					GetAfterLast( std::string haystack, std::string needle );
	std::string					GetToLast( std::string haystack, std::string needle );
	std::vector< std::string >	Split_Chr( std::string &S, CHAR D );
	std::vector< std::string >	Split_String( std::string &S, std::string D );
	std::string					GetDirectoryFile( std::string File );
	std::vector< std::string >	GetFilesInPath( std::string Path );
	void						AddToLogFileA( char *szFile, char *szLog, ... );
	void						BaseUponModule( HMODULE hModule );

private:
	std::string					Directory;
};

extern CAppTools GApp;

#endif