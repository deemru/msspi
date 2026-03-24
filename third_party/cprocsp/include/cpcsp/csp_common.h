#ifndef _CSP_COMMON_H_INCLUDED_
#define _CSP_COMMON_H_INCLUDED_

#define BUILD_YEAR	"2026"

#ifdef HAVE_CPRO_CONFIG_H
#ifdef DARWIN
#   include <stdint.h>
#endif //DARWIN
#include "myconfig.h"
#elif !defined DEVL && !defined CSP_LITE && !defined _WIN64 /* no config.h :Windows или примеры из doxygen*/
#if !defined(UNIX)
# define PATH_MAX MAX_PATH
#endif
# define HAVE_STDLIB_H 1
#else
#if defined _WIN64
# define PATH_MAX MAX_PATH
# define HAVE_STDLIB_H 1
#endif
#endif /* хотели Windows */

#include "cpcsp/processor_type.h"

//TODO: У нас определений UNUSED(x) штук 20-30, и некоторые кривые
#ifndef UNUSED
    #define UNUSED(x) (void)(x)
#endif

#if defined DEBUG && !defined _DEBUG
#   define _DEBUG 1
#endif
#if defined _DEBUG && !defined DEBUG
# define DEBUG 1
#endif

/*#define UNICODE
#define _UNICODE
*/

/* Security levels for SECURITY_LEVEL #define
 * Упорядочены по возрастанию. Так что нужно делать, например, так:
 *   #if SECURITY_LEVEL >= KB1
 */

#define KC1 1
#define KC2 2
#define KC3 3
#define KB1 4
#define KB2 5
#define KA1 6

#ifndef SECURITY_LEVEL
#define SECURITY_LEVEL KC1
#endif

#ifdef UNIX
# define _POSIX_PTHREAD_SEMANTICS 1 /* Must be defined for pthreads */
# if !defined _REENTRANT
#   define _REENTRANT 1 /* Must be defined for pthreads */
# endif	/* !_REENTRANT */
# define SUPPORT_RESOURCE_STD 1 /* Should be default on UNIX */
# define MAX_PATH PATH_MAX
/* Some kind of cheating?  For pthread...settype __USE_UNIX98 must be defined */
# if defined LINUX && !(defined __GNUC__ && (__GNUC__ == 4 && __GNUC_MINOR__ > 6) || __GNUC__ >= 5)
#  if !defined _XOPEN_SOURCE
#   define _XOPEN_SOURCE 700
#  endif /* !_XOPEN_SOURCE */
# endif /* LINUX && gcc-version < 4.7 */
#else /* UNIX */
# define X_DISPLAY_MISSING 1 /* We don't have X, do we? */
#endif /* UNIX */

#if defined DEVL && !defined CSP_LITE
# define CSP_LITE 1
#endif
#ifdef CSP_LITE
# define EXCLUDE_READER 1
#endif

#if defined HAVE_BUILTIN_OFFSETOF
#define CPRO_OFFSETOF(TYPE, MEMBER) __builtin_offsetof(TYPE,MEMBER)
#else // HAVE_BUILTIN_OFFSETOF
//-V:CPRO_OFFSETOF:221
#define CPRO_OFFSETOF(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif // HAVE_BUILTIN_OFFSETOF

// Enable CryptoPro specific parts of shared sdk sources
#define CPCSP_BUILD 1

#ifdef UNIX
typedef struct __TSupCSPPaths__
{
    const char * csp_static_root;   /* CSP_STATIC_ROOT */
    const char * csp_etc_dir;       /* CSP_ETC_DIR */
    const char * csp_volatile_dir;  /* CSP_VOLATILE_ROOT */
    const char * csp_floppy_root;   /* CSP_FLOPPY_ROOT */
    const char * csp_users_dir;     /* CSP_USERS_DIR */
    const char * csp_dsrf_dir;	    /* CSP_DSRF_DIR */
    const char * csp_protected_dir; /* CSP_PROTECTED_DIR */
    const char * csp_bin_dir;	    /* CSP_BIN_DIR */
    const char * csp_cp1251_ldir;   /* CSP_CP1251_LDIR */
    const char * csp_cp866_ldir;    /* CSP_CP866_LDIR */
    const char * csp_def_ldir;	    /* CSP_DEF_LDIR */
    const char * csp_iso8859_ldir;  /* CSP_ISO88595_LDIR */
    const char * csp_koi8r_ldir;    /* CSP_KOI8R_LDIR */
    const char * csp_utf8_ldir;	    /* CSP_UTF8_LDIR */
    const char * csp_lib_dir;	    /* CSP_LIB_DIR */
    const char * csp_sbin_dir;	    /* CSP_SBIN_DIR */
} TSupCSPPaths;
#ifdef __cplusplus
extern "C" {
#endif
extern const TSupCSPPaths * csp_get_paths(void);
#ifdef __cplusplus
}
#endif
#define CSP_STATIC_ROOT	(csp_get_paths()->csp_static_root)
#define CSP_ETC_DIR	(csp_get_paths()->csp_etc_dir)
#define CSP_VOLATILE_ROOT	(csp_get_paths()->csp_volatile_dir)
#define CSP_FLOPPY_ROOT	(csp_get_paths()->csp_floppy_root)
#define CSP_USERS_DIR	(csp_get_paths()->csp_users_dir)
#define CSP_DSRF_DIR	(csp_get_paths()->csp_dsrf_dir)
#define CSP_PROTECTED_DIR	(csp_get_paths()->csp_protected_dir)
#define CSP_BIN_DIR	(csp_get_paths()->csp_bin_dir)
#define CSP_CP1251_LDIR	(csp_get_paths()->csp_cp1251_ldir)
#define CSP_CP866_LDIR	(csp_get_paths()->csp_cp866_ldir)
#define CSP_DEF_LDIR	(csp_get_paths()->csp_def_ldir)
#define CSP_ETC_DIR	(csp_get_paths()->csp_etc_dir)
#define CSP_ISO88595_LDIR	(csp_get_paths()->csp_iso8859_ldir)
#define CSP_KOI8R_LDIR	(csp_get_paths()->csp_koi8r_ldir)
#define CSP_UTF8_LDIR	(csp_get_paths()->csp_utf8_ldir)
#define CSP_LIB_DIR	(csp_get_paths()->csp_lib_dir)
#define CSP_SBIN_DIR	(csp_get_paths()->csp_sbin_dir)
#endif	/* UNIX */
#endif /* _CSP_COMMON_H_INCLUDED_ */
