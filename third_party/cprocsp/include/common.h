#ifndef _COMMON_H_INCLUDED_
#define _COMMON_H_INCLUDED_

#define BUILD_YEAR	"2023"

/* Code types for USE_CODE #define */
#define USE_CODE_C	    1
#define USE_CODE_ASM	    2
#define USE_CODE_ASM64	    3
#define USE_CODE_ASM_E2K64  4
#define USE_CODE_ASM_ARM64  5

/* Processor types for PROCESSOR_TYPE #define */
#define PROC_TYPE_SPARC 1
#define PROC_TYPE_I386  2
#define PROC_TYPE_X64	3
#define PROC_TYPE_PPC32	4
#define PROC_TYPE_PPC64	5
#define PROC_TYPE_ARM	6
#define PROC_TYPE_ARM64 7
#define PROC_TYPE_MIPS32 8
#define PROC_TYPE_E2K32 9
#define PROC_TYPE_E2K64 10
#define PROC_TYPE_RISCV64 11

#ifdef HAVE_CONFIG_H
#ifdef DARWIN
#   include <stdint.h> 
#endif //DARWIN
#include "myconfig.h"
#elif !defined DEVL && !defined CSP_LITE && !defined _WIN64 /* no config.h :Windows или примеры из doxygen*/
#if !defined(UNIX)
# define PATH_MAX MAX_PATH
#endif
# define HAVE_STDLIB_H 1
# define HAVE_LIMITS_H 1
#else
#if defined _WIN64
# define PATH_MAX MAX_PATH
# define HAVE_STDLIB_H 1
# define HAVE_LIMITS_H 1 
#endif
#endif /* хотели Windows */

#if !defined(PROCESSOR_TYPE)
    /* 
     * Для автоопределение согласно:
     * TODO:XXX вставить ссылку на MSDN
     */
#  if defined(_WIN32)
#    if defined(_M_IX86)
#      define PROCESSOR_TYPE PROC_TYPE_I386
#    elif defined(_M_ARM64)
#      define PROCESSOR_TYPE PROC_TYPE_ARM64
#    elif defined(_M_ARM64EC)
#      define PROCESSOR_TYPE PROC_TYPE_ARM64
#    elif defined(_M_X64)
#      define PROCESSOR_TYPE PROC_TYPE_X64
#    endif //defined(_M_IX86) or defined(_M_X64)
#  endif //defined(_WIN32)
#endif //defined(PROCESSOR_TYPE)
    /*
     * В нашей сборке под Mac OS X, AIX, Solaris и пр. 
     * PROCESSOR_TYPE определяется в configure
     */
#if !defined(PROCESSOR_TYPE)
    /* 
     * Для драйверов и примеров автоопределение согласно:
     * Agner Fog, "Calling conventions for different C++ 
     * compilers and operating systems",
     * <http://www.agner.org/optimize/calling_conventions.pdf>
     */
#  if defined(__amd64) || defined(__x86_64__)
#    define PROCESSOR_TYPE PROC_TYPE_X64
#  elif defined(__i386__) || defined(__i386)
#    define PROCESSOR_TYPE PROC_TYPE_I386
#  elif defined(__powerpc64__)
/* Linux/PPC64 */
#    define PROCESSOR_TYPE PROC_TYPE_PPC64
#  elif defined(__powerpc__) || defined(__POWERPC__)
       /*
        * Дополнительно документация IBM
	* <http://publib.boulder.ibm.com/infocenter/comphelp/v8v101/index.jsp?topic=%2Fcom.ibm.xlcpp8a.doc%2Fcompiler%2Fref%2Fruopt64b.htm>
	* TODO:XX старый компилятор, ссылку обновить и проверить
	*/
#    if __64BIT__ 
#      define PROCESSOR_TYPE PROC_TYPE_PPC64
#    else
#      define PROCESSOR_TYPE PROC_TYPE_PPC32
#    endif
     /*
      * Дополнительно документация Oracle(Sun)
      * <http://docs.oracle.com/cd/E19060-01/stud8.compiler/817-0926/Comp_Options_App.html#15342>
      * TODO:XX старый компилятор, ссылку обновить и проверить
      */
#  elif defined(__sparc)
#    define PROCESSOR_TYPE PROC_TYPE_SPARC
#  elif defined(__sparcv9)
       // TODO:XXX Смотри:
       // D:\4_0\build\CSP\src\RuNetCSP\param.c
       // D:\4_0\build\CSP\src\RuNetCSP\G28147C.c
#    define PROCESSOR_TYPE PROC_TYPE_SPARC
#  elif defined(__arm64__) || defined(__aarch64__)
#    define PROCESSOR_TYPE PROC_TYPE_ARM64
#  elif defined(__ARM_ARCH__) || defined(__arm__)
       // TODO:
       // Вставить ссылку
       // Возможно, когда-нибудь эти ARM-ы придётся различать
#    define PROCESSOR_TYPE PROC_TYPE_ARM
#  elif defined(__mips__)
#    define PROCESSOR_TYPE PROC_TYPE_MIPS32
#  elif defined(__e2k__)
#    if defined(__ptr64__)
#       define PROCESSOR_TYPE PROC_TYPE_E2K64
#    else
#       define PROCESSOR_TYPE PROC_TYPE_E2K32
#    endif 
#  elif defined(__riscv)
#	define PROCESSOR_TYPE PROC_TYPE_RISCV64
#  endif
#endif //defined(PROCESSOR_TYPE)
#if !defined(PROCESSOR_TYPE)
#  error "PROCESSOR_TYPE - Can't autodected"
#endif //defined(PROCESSOR_TYPE)

#if !defined(USE_CODE)
#  if defined(DISABLE_SSE_AVX) || defined (_M_ARM64) || defined (_M_ARM64EC)
#    define USE_CODE USE_CODE_C
#  else // defined(DISABLE_SSE_AVX)
#    if PROCESSOR_TYPE == PROC_TYPE_I386
#      define USE_CODE USE_CODE_ASM
#    elif PROCESSOR_TYPE == PROC_TYPE_X64
#      define USE_CODE USE_CODE_ASM64
#    elif PROCESSOR_TYPE == PROC_TYPE_E2K64
#      define USE_CODE USE_CODE_ASM_E2K64
#    elif PROCESSOR_TYPE == PROC_TYPE_ARM64
#      define USE_CODE USE_CODE_ASM_ARM64
#    else
#      define USE_CODE USE_CODE_C
#    endif /* PROCESSOR_TYPE_* */
#  endif // defined(DISABLE_SSE_AVX)
#endif /* !USE_CODE */
#if !defined(USE_CODE)
#  error "USE_CODE - Can't autodected"
#endif // !defined(USE_CODE)

    //TODO: Переименовать 
    //TODO:XXXX Где-то HAVE_MMX_INSTRUCTIONS используется не по назначению
#if !defined(HAVE_MMX_INSTRUCTIONS)
#  if (PROCESSOR_TYPE == PROC_TYPE_X64) || \
      (PROCESSOR_TYPE == PROC_TYPE_I386 && !defined(IOS))
#    define HAVE_MMX_INSTRUCTIONS 1 // Для драйвера может потребоваться
      				    // захват FPU
#  endif /* PROCESSOR_TYPE_* */
#endif /* !defined(HAVE_MMX_INSTRUCTIONS) */


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
#ifdef UNIX
#define _ANTI_STR _TEXT("%s")
#else
#define _ANTI_STR _TEXT("%S")
#endif

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
# define Sleep(a) usleep((a)*1000)
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
#endif /* _COMMON_H_INCLUDED_ */
