#ifndef __PRIV_H__
#define __PRIV_H__

extern BOOL GetDebugPrivileges( void );
extern bool SetPrivilege( HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege );

#endif