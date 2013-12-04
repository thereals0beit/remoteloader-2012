#include "stdafx.h"
#include "Priv.h"

bool SetPrivilege( HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege )
{
	TOKEN_PRIVILEGES tp;
	LUID luid;
	TOKEN_PRIVILEGES tpPrevious;
	DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);

	if(!LookupPrivilegeValue( NULL, lpszPrivilege, &luid )) 
		return false;

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = 0;

	AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), &tpPrevious, &cbPrevious);
	
	if (GetLastError() != ERROR_SUCCESS) 
		return false;

	tpPrevious.PrivilegeCount = 1;
	tpPrevious.Privileges[0].Luid = luid;
	
	if (bEnablePrivilege) 
		tpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
	else
		tpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED & tpPrevious.Privileges[0].Attributes);

	AdjustTokenPrivileges( hToken, FALSE, &tpPrevious, cbPrevious, NULL, NULL );
	
	if( GetLastError() != ERROR_SUCCESS )
		return false;

	return true;
}

BOOL GetDebugPrivileges( void )
{
	HANDLE hToken;

	bool bOK = false;

	if( OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken ) )
	{
		if( SetPrivilege( hToken, SE_DEBUG_NAME, TRUE ) )
		{
			bOK = true;
		}

		CloseHandle( hToken );
	}

	return bOK;
}