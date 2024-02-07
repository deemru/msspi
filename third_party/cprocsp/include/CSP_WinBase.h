/****************************************************************************
*                                                                           *
* windef.h -- Basic Windows Type Definitions                                *
*                                                                           *
* Copyright (c) 1985-1999, Microsoft Corp. All rights reserved.             *
*                                                                           *
****************************************************************************/


#ifndef _WINBASE_
#define _WINBASE_

#ifdef __cplusplus
extern "C" {
#endif

#define OutputDebugStringA(buf)

#if !defined(_KERNEL32_)
#define WINBASEAPI DECLSPEC_IMPORT
#else
#define WINBASEAPI
#endif

#ifndef _FILETIME_
#define _FILETIME_
typedef struct _FILETIME
    {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
    } 	FILETIME;

typedef struct _FILETIME *PFILETIME;

typedef struct _FILETIME *LPFILETIME;

#endif // !_FILETIME

//
// System time is represented with the following structure:
//

typedef struct _SYSTEMTIME {
    WORD wYear;
    WORD wMonth;
    WORD wDayOfWeek;
    WORD wDay;
    WORD wHour;
    WORD wMinute;
    WORD wSecond;
    WORD wMilliseconds;
} SYSTEMTIME, *PSYSTEMTIME, *LPSYSTEMTIME;

WINBASEAPI
VOID
WINAPI
GetSystemTime(
    LPSYSTEMTIME lpSystemTime
    );

WINBASEAPI
BOOL 
WINAPI
SystemTimeToFileTime(
    CONST SYSTEMTIME *lpSystemTime,  // system time
    LPFILETIME lpFileTime            // file time
    );

WINBASEAPI
VOID
WINAPI
GetSystemTimeAsFileTime(
    OUT LPFILETIME lpSystemTimeAsFileTime
    );

WINBASEAPI
LONG
WINAPI
CompareFileTime(
    CONST FILETIME *lpFileTime1,
    CONST FILETIME *lpFileTime2
    );

WINBASEAPI
BOOL
WINAPI
FileTimeToSystemTime(
    IN CONST FILETIME *lpFileTime,
    OUT LPSYSTEMTIME lpSystemTime
    );

#ifdef __cplusplus
}
#endif

#endif // _WINBASE_
