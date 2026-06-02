/*
 * Copyright (c) 2000, компания Крипто-Про
 *
 * Разрешается повторное распространение и использование как в виде исходного
 * кода, так и в двоичной форме, с изменениями или без, при соблюдении
 * следующих условий:
 *
 * 1) При повторном распространении исходного кода должно оставаться
 *    указанное выше уведомление об авторском праве, этот список условий
 *    и последующий отказ от гарантий.
 *
 * 2) При повторном распространении двоичного кода должно сохраняться
 *    указанная выше информация об авторском праве, этот список условий
 *    и последующий отказ от гарантий в документации и/или в других материалах,
 *    поставляемых при распространении.
 *
 * ЭТА ПРОГРАММА ПРЕДОСТАВЛЕНА БЕСПЛАТНО ВЛАДЕЛЬЦАМИ АВТОРСКИХ ПРАВ И/ИЛИ
 * ДРУГИМИ СТОРОНАМИ "КАК ОНА ЕСТЬ" БЕЗ КАКОГО-ЛИБО ВИДА ГАРАНТИЙ, ВЫРАЖЕННЫХ
 * ЯВНО ИЛИ ПОДРАЗУМЕВАЕМЫХ, ВКЛЮЧАЯ, НО НЕ ОГРАНИЧИВАЯСЬ ИМИ, ПОДРАЗУМЕВАЕМЫЕ
 * ГАРАНТИИ КОММЕРЧЕСКОЙ ЦЕННОСТИ И ПРИГОДНОСТИ ДЛЯ КОНКРЕТНОЙ ЦЕЛИ. НИ В КОЕМ
 * СЛУЧАЕ, ЕСЛИ НЕ ТРЕБУЕТСЯ СООТВЕТСТВУЮЩИМ ЗАКОНОМ, ИЛИ НЕ УСТАНОВЛЕНО В
 * УСТНОЙ ФОРМЕ, НИ ОДИН ВЛАДЕЛЕЦ АВТОРСКИХ ПРАВ И НИ ОДНО ДРУГОЕ ЛИЦО, КОТОРОЕ
 * МОЖЕТ ИЗМЕНЯТЬ И/ИЛИ ПОВТОРНО РАСПРОСТРАНЯТЬ ПРОГРАММУ, КАК БЫЛО СКАЗАНО
 * ВЫШЕ, НЕ НЕСЁТ ОТВЕТСТВЕННОСТИ, ВКЛЮЧАЯ ЛЮБЫЕ ОБЩИЕ, СЛУЧАЙНЫЕ, СПЕЦИАЛЬНЫЕ
 * ИЛИ ПОСЛЕДОВАВШИЕ УБЫТКИ, В СЛЕДСТВИИ ИСПОЛЬЗОВАНИЯ ИЛИ НЕВОЗМОЖНОСТИ
 * ИСПОЛЬЗОВАНИЯ ПРОГРАММЫ (ВКЛЮЧАЯ, НО НЕ ОГРАНИЧИВАЯСЬ ПОТЕРЕЙ ДАННЫХ,
 * ИЛИ ДАННЫМИ, СТАВШИМИ НЕПРАВИЛЬНЫМИ, ИЛИ ПОТЕРЯМИ ПРИНЕСЕННЫМИ ИЗ-ЗА ВАС ИЛИ
 * ТРЕТЬИХ ЛИЦ, ИЛИ ОТКАЗОМ ПРОГРАММЫ РАБОТАТЬ СОВМЕСТНО С ДРУГИМИ ПРОГРАММАМИ),
 * ДАЖЕ ЕСЛИ ТАКОЙ ВЛАДЕЛЕЦ ИЛИ ДРУГОЕ ЛИЦО БЫЛИ ИЗВЕЩЕНЫ О ВОЗМОЖНОСТИ
 * ТАКИХ УБЫТКОВ.
 *
 * Copyright (c) 2000, Crypto-Pro Company All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1) Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2) Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef PROCESSOR_TYPE_H_INCLUDED
#define PROCESSOR_TYPE_H_INCLUDED

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

#if !defined(SIZEOF_VOID_P)
#  if PROCESSOR_TYPE == PROC_TYPE_SPARC
#     if defined(__sparcv9)
#	define SIZEOF_VOID_P 8
#     else
#	define SIZEOF_VOID_P 4
#     endif /* __sparcv9 */
#  elif PROCESSOR_TYPE == PROC_TYPE_I386 || PROCESSOR_TYPE == PROC_TYPE_PPC32 || PROCESSOR_TYPE == PROC_TYPE_MIPS32 || PROCESSOR_TYPE == PROC_TYPE_E2K32 || PROCESSOR_TYPE == PROC_TYPE_ARM
#    define SIZEOF_VOID_P 4
#  elif PROCESSOR_TYPE == PROC_TYPE_X64 || PROCESSOR_TYPE == PROC_TYPE_PPC64 || PROCESSOR_TYPE == PROC_TYPE_ARM64 || PROCESSOR_TYPE == PROC_TYPE_E2K64 || PROCESSOR_TYPE == PROC_TYPE_RISCV64
#    define SIZEOF_VOID_P 8
#  else
#    error PROCESSOR_TYPE not defined
#  endif /* PROCESSOR_TYPE */
#endif /* !defined(SIZEOF_VOID_P) */

#if PROCESSOR_TYPE == PROC_TYPE_SPARC || PROCESSOR_TYPE == PROC_TYPE_PPC32 || PROCESSOR_TYPE == PROC_TYPE_PPC64 || ( defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__ )
#define WORDS_BIGENDIAN 1
#endif

#endif // PROCESSOR_TYPE_H_INCLUDED
