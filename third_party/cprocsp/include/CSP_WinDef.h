/****************************************************************************
*                                                                           *
* windef.h -- Basic Windows Type Definitions                                *
*                                                                           *
* Copyright (c) 1985-1999, Microsoft Corp. All rights reserved.             *
*                                                                           *
****************************************************************************/


#ifndef _WINDEF_
#define _WINDEF_

#include "common.h"

#ifndef NO_STRICT
#ifndef STRICT
#define STRICT 1
#endif
#endif /* NO_STRICT */


#ifdef __cplusplus
extern "C" {
#endif

#ifndef WINVER
#define WINVER 0x0500
#endif /* WINVER */

/*
 * BASETYPES is defined in ntdef.h if these types are already defined
 */

#ifndef BASETYPES
#define BASETYPES
typedef unsigned long ULONG;
typedef ULONG *PULONG;
typedef unsigned short USHORT;
typedef USHORT *PUSHORT;
typedef unsigned char UCHAR;
typedef UCHAR *PUCHAR;
typedef char *PSZ;
#endif  /* !BASETYPES */

#ifndef NULL
#ifdef __cplusplus
#define NULL    0
#else
#define NULL    ((void *)0)
#endif
#endif

#ifndef FALSE
#define FALSE               0
#endif

#ifndef TRUE
#define TRUE                1
#endif

#ifndef IN
#define IN
#endif

#ifndef OUT
#define OUT
#endif

#ifndef OPTIONAL
#define OPTIONAL
#endif

#undef far
#undef near
#undef pascal

#define far
#define near

#if (!defined(_MAC)) && ((defined(_MSC_VER) && (_MSC_VER >= 800)) || defined(_STDCALL_SUPPORTED))
#define pascal __stdcall
#else
#define pascal
#endif

#if defined(DOSWIN32) || defined(_MAC)
#define cdecl _cdecl
#ifndef CDECL
#define CDECL _cdecl
#endif
#else
#define cdecl
#ifndef CDECL
#define CDECL
#endif
#endif

#ifdef _MAC
#define CALLBACK    PASCAL
#define WINAPI      CDECL
#define WINAPIV     CDECL
#define APIENTRY    WINAPI
#define APIPRIVATE  CDECL
#ifdef _68K_
#define PASCAL      __pascal
#else
#define PASCAL
#endif
#elif (defined(_MSC_VER) && (_MSC_VER >= 800)) || defined(_STDCALL_SUPPORTED)
#define CALLBACK    __stdcall
#define WINAPI      __stdcall
#define WINAPIV     __cdecl
#define APIENTRY    WINAPI
#define APIPRIVATE  __stdcall
#define PASCAL      __stdcall
#else
#define CALLBACK
#define WINAPI
#define WINAPIV
#define APIENTRY    WINAPI
#define APIPRIVATE
#define PASCAL      pascal
#endif

#undef FAR
#undef  NEAR
#define FAR                 far
#define NEAR                near
#ifndef CONST
#define CONST               const
#endif

/*Определения из WinNT.h */
/* Basics*/

#ifndef VOID
#define VOID void
typedef char CHAR;
typedef short SHORT;
#ifndef LONG
typedef int LONG;
#endif
typedef unsigned int       DWORD;	/* XXXX icc говорит, что с этим типом есть проблемы ???? */
#ifndef _HRESULT_DEFINED
#define _HRESULT_DEFINED
typedef LONG HRESULT;
#endif /* !_HRESULT_DEFINED */
#endif /* VOID*/

typedef int                 BOOL;
typedef unsigned char       BYTE;
typedef unsigned short      WORD;
typedef float               FLOAT;
typedef FLOAT               *PFLOAT;
typedef BOOL near           *PBOOL;
typedef BOOL far            *LPBOOL;
typedef BYTE near           *PBYTE;
typedef BYTE far            *LPBYTE;
typedef CONST BYTE far      *LPCBYTE;
typedef int near            *PINT;
typedef int far             *LPINT;
typedef WORD near           *PWORD;
typedef WORD far            *LPWORD;
typedef long far            *LPLONG;
typedef DWORD near          *PDWORD;
typedef DWORD far           *LPDWORD;
typedef void far            *LPVOID;
typedef CONST void far      *LPCVOID;
typedef void *PVOID;

typedef int                 INT;
typedef unsigned int        UINT;
typedef unsigned int        *PUINT;

#if defined WIN32
typedef unsigned __int64 ULONGLONG;
typedef __int64 LONGLONG;
#else
#if defined(__GNUC__) && defined(IOS) && defined(PROCESSOR_TYPE) && PROCESSOR_TYPE == PROC_TYPE_ARM
#define SUP_ALIGN8 __attribute__((__aligned__(8)))
#else
#define SUP_ALIGN8
#endif
typedef unsigned long long ULONGLONG SUP_ALIGN8;
typedef long long LONGLONG SUP_ALIGN8;
#endif

#ifndef _DWORDLONG_
#define _DWORDLONG_
typedef ULONGLONG  DWORDLONG;
typedef DWORDLONG *PDWORDLONG;
#endif

#if (defined(_M_IX86) || defined(_M_ALPHA) || defined(_M_IA64) || defined(_M_AMD64)) && !defined(MIDL_PASS)
#define DECLSPEC_IMPORT     __declspec(dllimport)
#else
#define DECLSPEC_IMPORT
#endif

#if 0
#if defined (UNIX) || (defined (CSP_LITE) && defined (CSP_INTERNAL))
# if defined (UNIX) 
#  ifdef STDC_HEADERS
#    include <stdlib.h>
#    include <stddef.h>
#  else /* STDC_HEADERS */
#    ifdef HAVE_STDLIB_H
#      include <stdlib.h>
#    endif
#  endif /* STDC_HEADERS */
#  include <wchar.h>
# else /* (defined (CSP_LITE) && defined (CSP_INTERNAL)) */
#  include "csplitecrt.h"
# endif
  ...
#else
# if defined (CSP_LITE)
#  include "reader/ddk4.h"
# else /* !defined (CSP_LITE) */
#  include <WinDef.h>
# endif
#endif
#endif

#ifdef CSP_LITE
# ifndef CSP_DRIVER
#   include "csplitecrt.h"
# else
#   if defined DARWIN
	// TODO:XXX:
	#if !defined __cplusplus
	    typedef __WCHAR_TYPE__ wchar_t;
	    typedef __SIZE_TYPE__ size_t;
	#endif
#   endif
# endif
#else
# ifdef STDC_HEADERS
#   include <stdlib.h>
#   include <stddef.h>
# else /* STDC_HEADERS */
#   ifdef HAVE_STDLIB_H
#     include <stdlib.h>
#   endif
# endif /* STDC_HEADERS */
# include <wchar.h>
#endif /* CSP_LITE */

typedef wchar_t WCHAR;   /* wc,   16-bit UNICODE character */
typedef CONST wchar_t *LPCWSTR, *PCWSTR;

#ifndef __TCHAR_DEFINED
#define __TCHAR_DEFINED

#if defined( UNICODE )
typedef wchar_t TCHAR, *PTCHAR;
typedef wint_t _TINT;
#else
typedef char TCHAR, *PTCHAR;
typedef int _TINT;
#endif

#endif /* __TCHAR_DEFINED */

#ifndef GUID_DEFINED
#define GUID_DEFINED
typedef struct _GUID {
    unsigned long  Data1;
    unsigned short Data2;
    unsigned short Data3;
    unsigned char  Data4[ 8 ];
} GUID;
#endif

#ifdef STRICT
typedef void *HANDLE;
#define DECLARE_HANDLE(name) struct name##_ { int unused; }; typedef struct name##_ *name
#else
typedef PVOID HANDLE;
#define DECLARE_HANDLE(name) typedef HANDLE name
#endif
typedef HANDLE *PHANDLE;

/*typedef HANDLE       HWND;*/
DECLARE_HANDLE(HINSTANCE);
DECLARE_HANDLE(HWND);
typedef HINSTANCE HMODULE;      /* HMODULEs can be used in place of HINSTANCEs */
typedef HANDLE HLOCAL;

/*
#ifndef NT_INCLUDED
#include <winnt.h>
#endif  NT_INCLUDED */

/* Types use for passing & returning polymorphic values 
typedef UINT_PTR            WPARAM;
typedef LONG_PTR            LPARAM;
typedef LONG_PTR            LRESULT;
*/
/*Определения из BaseTsd.h*/
#if SIZEOF_VOID_P == 8 || defined(_WIN64)
typedef long long INT_PTR, *PINT_PTR;
typedef unsigned long long UINT_PTR, *PUINT_PTR;
typedef long long LONG_PTR, *PLONG_PTR;
typedef unsigned long long ULONG_PTR, *PULONG_PTR;
#elif !defined(UNIX) || SIZEOF_VOID_P == 4
typedef int INT_PTR, *PINT_PTR;
typedef unsigned int UINT_PTR, *PUINT_PTR;
typedef long LONG_PTR, *PLONG_PTR;
typedef unsigned long ULONG_PTR, *PULONG_PTR;
#else
#error "SIZEOF_VOID_P not defined"
#endif

typedef ULONG_PTR DWORD_PTR, *PDWORD_PTR;
/*Конец определений из BaseTsd.h*/

#define INVALID_HANDLE_VALUE ((HANDLE)(LONG_PTR)-1)

#define MAKEWORD(a, b)      ((WORD)(((BYTE)((DWORD_PTR)(a) & 0xff)) | ((WORD)((BYTE)((DWORD_PTR)(b) & 0xff))) << 8))
#define MAKELONG(a, b)      ((LONG)(((WORD)((DWORD_PTR)(a) & 0xffff)) | ((DWORD)((WORD)((DWORD_PTR)(b) & 0xffff))) << 16))
#define LOWORD(l)           ((WORD)((DWORD_PTR)(l) & 0xffff))
#define HIWORD(l)           ((WORD)((DWORD_PTR)(l) >> 16))
#define LOBYTE(w)           ((BYTE)((DWORD_PTR)(w) & 0xff))
#define HIBYTE(w)           ((BYTE)((DWORD_PTR)(w) >> 8))

typedef int (CALLBACK *FARPROC)(void);
typedef int (CALLBACK *NEARPROC)(void);
typedef int (CALLBACK *PROC)(void);

/*
// ANSI (Multi-byte Character) types
*/
typedef CHAR *PCHAR;
typedef CHAR *LPCH, *PCH;

typedef CONST CHAR *LPCSTR, *PCSTR;
typedef CONST CHAR *LPCCH, *PCCH;
typedef CHAR *NPSTR;
typedef CHAR *LPSTR, *PSTR;

typedef WCHAR *LPWSTR, *PWSTR;

typedef TCHAR *LPTSTR;
typedef CONST TCHAR *LPCTSTR, *PCTSTR;
/*typedef CONST CHAR *LPCSTR, *PCSTR;*/


typedef WORD                ATOM;

/*Определения из WinNT.h*/
/*
typedef union _LARGE_INTEGER {
    struct {
        DWORD LowPart;
        LONG HighPart;
    };
    struct {
        DWORD LowPart;
        LONG HighPart;
    } u;
//    LONGLONG QuadPart;
} LARGE_INTEGER;
*/
typedef struct _LARGE_INTEGER {
        DWORD LowPart;
        LONG HighPart;
} LARGE_INTEGER;

//
// Locally Unique Identifier
//

typedef struct _LUID {
    DWORD LowPart;
    LONG HighPart;
} LUID, *PLUID;

#define LANG_NEUTRAL                     0x00
#define LANG_ENGLISH                     0x09
#define LANG_RUSSIAN                     0x19
#define SUBLANG_NEUTRAL                  0x00    // language neutral
#define SUBLANG_DEFAULT                  0x01    // user default

#define MAKELANGID(p, s)       ((((WORD  )(s)) << 10) | (WORD  )(p))
#define PRIMARYLANGID(lgid)    ((WORD  )(lgid) & 0x3ff)
#define SUBLANGID(lgid)        ((WORD  )(lgid) >> 10)

#define ZeroMemory(Destination,Length) memset((Destination),0,(Length))
#define CopyMemory(Destination,Source,Length) memcpy((Destination),(Source),(Length))
#define FillMemory(Destination,Length,Fill) memset((Destination),(Fill),(Length))
/*Конец определений из WinNT.h*/

#include "CSP_WinBase.h"

/*Начало определений из WinNls.h*/

//
//  Code Page Default Values.
//
#define CP_ACP                      0           // default to ANSI code page
#define CP_UTF8                     65001
#define CP_UTF16LE                  1200
#define CP_ISO8859_5                28595

#define MB_PRECOMPOSED              0x01
#define MB_COMPOSITE                0x02
#define MB_USEGLYPHCHARS            0x04
#define MB_ERR_INVALID_CHARS        0x08

#define WC_DISCARDNS         0x0010
#define WC_SEPCHARS          0x0020
#define WC_DEFAULTCHAR       0x0040
#define WC_ERR_INVALID_CHARS 0x0080
#define WC_COMPOSITECHECK    0x0200
#define WC_NO_BEST_FIT_CHARS 0x0400


WINBASEAPI
int
WINAPI
MultiByteToWideChar(
  UINT CodePage,         // code page
  DWORD dwFlags,         // character-type options
  LPCSTR lpMultiByteStr, // string to map
  int cbMultiByte,       // number of bytes in string
  LPWSTR lpWideCharStr,  // wide-character buffer
  int cchWideChar        // size of buffer
);

WINBASEAPI
int
WINAPI
WideCharToMultiByte(
  UINT CodePage,            // code page
  DWORD dwFlags,            // performance and mapping flags
  LPCWSTR lpWideCharStr,    // wide-character string
  int cchWideChar,          // number of chars in string
  LPSTR lpMultiByteStr,     // buffer for new string
  int cbMultiByte,          // size of buffer
  LPCSTR lpDefaultChar,     // default for unmappable chars
  LPBOOL lpUsedDefaultChar  // set when default char used
);

/*Конец определений из WinNls.h*/

WINBASEAPI DWORD WINAPI GetLastError(void);

WINBASEAPI void WINAPI SetLastError(DWORD dwErr);   //Sets error code

#ifdef LEGACY_FORMAT_MESSAGE_IMPL

WINBASEAPI
DWORD
WINAPI
FormatMessage(
    IN DWORD dwFlags,
    IN LPCVOID lpSource,
    IN DWORD dwMessageId,
    IN DWORD dwLanguageId,
    OUT LPSTR lpBuffer,
    IN DWORD nSize,
    IN void *Arguments
    );

#define FormatMessageA FormatMessage

#else

#if defined (_MSC_VER) || defined (__GNUC__)
#  if defined (__cplusplus) && !defined (IGNORE_LEGACY_FORMAT_MESSAGE_MSG) && !defined (__APPLE__)
#    if defined(_M_IX86) || defined(_M_X64) || defined(__amd64) || defined(__x86_64__) || defined(__i386__) || defined(__i386)
#      pragma message ("Your application will require at least CryptoPro CSP 4.0 R3. You can use LEGACY_FORMAT_MESSAGE_IMPL to support older versions.")
#    endif
#  endif
#endif

WINBASEAPI
DWORD
WINAPI
FormatMessageA(
    IN DWORD dwFlags,
    IN LPCVOID lpSource,
    IN DWORD dwMessageId,
    IN DWORD dwLanguageId,
    OUT LPSTR lpBuffer,
    IN DWORD nSize,
    IN void *Arguments
    );

WINBASEAPI
DWORD
WINAPI
FormatMessageW(
    IN DWORD dwFlags,
    IN LPCVOID lpSource,
    IN DWORD dwMessageId,
    IN DWORD dwLanguageId,
    OUT LPWSTR lpBuffer,
    IN DWORD nSize,
    IN void *Arguments
    );

#ifdef UNICODE
#    define FormatMessage FormatMessageW
#else
#    define FormatMessage FormatMessageA
#endif // UNICODE

#endif // LEGACY_FORMAT_MESSAGE_IMPL

#define FORMAT_MESSAGE_ALLOCATE_BUFFER 0x00000100
#define FORMAT_MESSAGE_IGNORE_INSERTS  0x00000200
#define FORMAT_MESSAGE_FROM_STRING     0x00000400
#define FORMAT_MESSAGE_FROM_HMODULE    0x00000800
#define FORMAT_MESSAGE_FROM_SYSTEM     0x00001000
#define FORMAT_MESSAGE_ARGUMENT_ARRAY  0x00002000
#define FORMAT_MESSAGE_MAX_WIDTH_MASK  0x000000FF

typedef ULONG_PTR SIZE_T, *PSIZE_T;
typedef LONG_PTR SSIZE_T, *PSSIZE_T;

// begin_ntddk begin_wdm begin_nthal begin_ntifs
//
//  The following are masks for the predefined standard access types
//

#define DELETE                           (0x00010000L)
#define READ_CONTROL                     (0x00020000L)
#define WRITE_DAC                        (0x00040000L)
#define WRITE_OWNER                      (0x00080000L)
#define SYNCHRONIZE                      (0x00100000L)

#define STANDARD_RIGHTS_REQUIRED         (0x000F0000L)

#define STANDARD_RIGHTS_READ             (READ_CONTROL)
#define STANDARD_RIGHTS_WRITE            (READ_CONTROL)
#define STANDARD_RIGHTS_EXECUTE          (READ_CONTROL)

#define STANDARD_RIGHTS_ALL              (0x001F0000L)

#define SPECIFIC_RIGHTS_ALL              (0x0000FFFFL)

//
// AccessSystemAcl access type
//

#define ACCESS_SYSTEM_SECURITY           (0x01000000L)

//
// MaximumAllowed access type
//

#define MAXIMUM_ALLOWED                  (0x02000000L)

//
//  These are the generic rights.
//

#define GENERIC_READ                     (0x80000000L)
#define GENERIC_WRITE                    (0x40000000L)
#define GENERIC_EXECUTE                  (0x20000000L)
#define GENERIC_ALL                      (0x10000000L)

//
// The FILE_READ_DATA and FILE_WRITE_DATA constants are also defined in
// devioctl.h as FILE_READ_ACCESS and FILE_WRITE_ACCESS. The values for these
// constants *MUST* always be in sync.
// The values are redefined in devioctl.h because they must be available to
// both DOS and NT.
//

#define FILE_READ_DATA            ( 0x0001 )    // file & pipe
#define FILE_LIST_DIRECTORY       ( 0x0001 )    // directory

#define FILE_WRITE_DATA           ( 0x0002 )    // file & pipe
#define FILE_ADD_FILE             ( 0x0002 )    // directory

#define FILE_APPEND_DATA          ( 0x0004 )    // file
#define FILE_ADD_SUBDIRECTORY     ( 0x0004 )    // directory
#define FILE_CREATE_PIPE_INSTANCE ( 0x0004 )    // named pipe


#define FILE_READ_EA              ( 0x0008 )    // file & directory

#define FILE_WRITE_EA             ( 0x0010 )    // file & directory

#define FILE_EXECUTE              ( 0x0020 )    // file
#define FILE_TRAVERSE             ( 0x0020 )    // directory

#define FILE_DELETE_CHILD         ( 0x0040 )    // directory

#define FILE_READ_ATTRIBUTES      ( 0x0080 )    // all

#define FILE_WRITE_ATTRIBUTES     ( 0x0100 )    // all

#define FILE_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF)

#define FILE_GENERIC_READ         (STANDARD_RIGHTS_READ     |\
                                   FILE_READ_DATA           |\
                                   FILE_READ_ATTRIBUTES     |\
                                   FILE_READ_EA             |\
                                   SYNCHRONIZE)


#define FILE_GENERIC_WRITE        (STANDARD_RIGHTS_WRITE    |\
                                   FILE_WRITE_DATA          |\
                                   FILE_WRITE_ATTRIBUTES    |\
                                   FILE_WRITE_EA            |\
                                   FILE_APPEND_DATA         |\
                                   SYNCHRONIZE)


#define FILE_GENERIC_EXECUTE      (STANDARD_RIGHTS_EXECUTE  |\
                                   FILE_READ_ATTRIBUTES     |\
                                   FILE_EXECUTE             |\
                                   SYNCHRONIZE)

#define FILE_SHARE_READ                 0x00000001  
#define FILE_SHARE_WRITE                0x00000002  
#define FILE_SHARE_DELETE               0x00000004  
#define FILE_ATTRIBUTE_READONLY             0x00000001  
#define FILE_ATTRIBUTE_HIDDEN               0x00000002  
#define FILE_ATTRIBUTE_SYSTEM               0x00000004  
#define FILE_ATTRIBUTE_DIRECTORY            0x00000010  
#define FILE_ATTRIBUTE_ARCHIVE              0x00000020  
#define FILE_ATTRIBUTE_DEVICE               0x00000040  
#define FILE_ATTRIBUTE_NORMAL               0x00000080  
#define FILE_ATTRIBUTE_TEMPORARY            0x00000100  
#define FILE_ATTRIBUTE_SPARSE_FILE          0x00000200  
#define FILE_ATTRIBUTE_REPARSE_POINT        0x00000400  
#define FILE_ATTRIBUTE_COMPRESSED           0x00000800  
#define FILE_ATTRIBUTE_OFFLINE              0x00001000  
#define FILE_ATTRIBUTE_NOT_CONTENT_INDEXED  0x00002000  
#define FILE_ATTRIBUTE_ENCRYPTED            0x00004000  
#define FILE_NOTIFY_CHANGE_FILE_NAME    0x00000001   
#define FILE_NOTIFY_CHANGE_DIR_NAME     0x00000002   
#define FILE_NOTIFY_CHANGE_ATTRIBUTES   0x00000004   
#define FILE_NOTIFY_CHANGE_SIZE         0x00000008   
#define FILE_NOTIFY_CHANGE_LAST_WRITE   0x00000010   
#define FILE_NOTIFY_CHANGE_LAST_ACCESS  0x00000020   
#define FILE_NOTIFY_CHANGE_CREATION     0x00000040   
#define FILE_NOTIFY_CHANGE_SECURITY     0x00000100   
#define FILE_ACTION_ADDED                   0x00000001   
#define FILE_ACTION_REMOVED                 0x00000002   
#define FILE_ACTION_MODIFIED                0x00000003   
#define FILE_ACTION_RENAMED_OLD_NAME        0x00000004   
#define FILE_ACTION_RENAMED_NEW_NAME        0x00000005   
#define MAILSLOT_NO_MESSAGE             ((DWORD)-1) 
#define MAILSLOT_WAIT_FOREVER           ((DWORD)-1) 
#define FILE_CASE_SENSITIVE_SEARCH      0x00000001  
#define FILE_CASE_PRESERVED_NAMES       0x00000002  
#define FILE_UNICODE_ON_DISK            0x00000004  
#define FILE_PERSISTENT_ACLS            0x00000008  
#define FILE_FILE_COMPRESSION           0x00000010  
#define FILE_VOLUME_QUOTAS              0x00000020  
#define FILE_SUPPORTS_SPARSE_FILES      0x00000040  
#define FILE_SUPPORTS_REPARSE_POINTS    0x00000080  
#define FILE_SUPPORTS_REMOTE_STORAGE    0x00000100  
#define FILE_VOLUME_IS_COMPRESSED       0x00008000  
#define FILE_SUPPORTS_OBJECT_IDS        0x00010000  
#define FILE_SUPPORTS_ENCRYPTION        0x00020000  
#define FILE_NAMED_STREAMS              0x00040000  
#define FILE_READ_ONLY_VOLUME           0x00080000  

#define FILE_BEGIN           0
#define FILE_CURRENT         1
#define FILE_END             2

#define CREATE_NEW          1
#define CREATE_ALWAYS       2
#define OPEN_EXISTING       3
#define OPEN_ALWAYS         4
#define TRUNCATE_EXISTING   5

/* Local Memory Flags */
#define LMEM_FIXED          0x0000
#define LMEM_MOVEABLE       0x0002
#define LMEM_NOCOMPACT      0x0010
#define LMEM_NODISCARD      0x0020
#define LMEM_ZEROINIT       0x0040
#define LMEM_MODIFY         0x0080
#define LMEM_DISCARDABLE    0x0F00
#define LMEM_VALID_FLAGS    0x0F72
#define LMEM_INVALID_HANDLE 0x8000

#define LHND                (LMEM_MOVEABLE | LMEM_ZEROINIT)
#define LPTR                (LMEM_FIXED | LMEM_ZEROINIT)

#define NONZEROLHND         (LMEM_MOVEABLE)
#define NONZEROLPTR         (LMEM_FIXED)

HLOCAL WINAPI LocalAlloc(
    IN UINT uFlags,
    IN SIZE_T uBytes);

HLOCAL WINAPI LocalFree(
    IN HLOCAL hMem );

/*

 Predefined Value Types.
*/

#define REG_NONE                    ( 0 )   /* No value type */
#define REG_SZ                      ( 1 )   /* Unicode nul terminated string */
#define REG_EXPAND_SZ               ( 2 )   /* Unicode nul terminated string */
                                            /* (with environment variable references) */
#define REG_BINARY                  ( 3 )   /* Free form binary */
#define REG_DWORD                   ( 4 )   /* 32-bit number */
#define REG_DWORD_LITTLE_ENDIAN     ( 4 )   /* 32-bit number (same as REG_DWORD) */
#define REG_DWORD_BIG_ENDIAN        ( 5 )   /* 32-bit number */
#define REG_LINK                    ( 6 )   /* Symbolic Link (unicode) */
#define REG_MULTI_SZ                ( 7 )   /* Multiple Unicode strings */
#define REG_RESOURCE_LIST           ( 8 )   /* Resource list in the resource map */
#define REG_FULL_RESOURCE_DESCRIPTOR ( 9 )  /* Resource list in the hardware description */
#define REG_RESOURCE_REQUIREMENTS_LIST ( 10 )
#define REG_QWORD                   ( 11 )  /* 64-bit number */
#define REG_QWORD_LITTLE_ENDIAN     ( 11 )  /* 64-bit number (same as REG_QWORD) */

#ifdef __cplusplus
}
#endif
#endif /* _CSP_WINDEF_ */

