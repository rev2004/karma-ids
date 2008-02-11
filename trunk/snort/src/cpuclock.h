#ifndef CPU_CLOCK_TICKS_H
#define CPU_CLOCK_TICKS_H

#include "debug.h"
#include "sf_types.h"  /* for UINT64 */

/* Assembly to find clock ticks. */
#ifdef WIN32
#include <windows.h>

/* INTEL WINDOWS */
__inline void __cputicks_msc(UINT64 *val)
{
  __int64 t;
  __asm
    {
      rdtsc;
      mov dword PTR [t],eax;
      mov dword PTR [t+4],edx;
    }
 *val = (UINT64)t;
}
#define get_clockticks(val) __cputicks_msc(&val)

/*
#define get_clockticks(val) \
    QueryPerformanceCounter((PLARGE_INTEGER)&val)
*/


#else
#include <unistd.h>

/* INTEL LINUX/BSD/.. */
#if (defined(__i386) || defined(__ia64) || defined(__amd64) )
#define get_clockticks(val) \
{ \
    u_int32_t a, d; \
    __asm__ __volatile__ ("rdtsc" : "=a" (a), "=d" (d));  \
    val = ((UINT64)a) | (((UINT64)d) << 32);  \
}
#else
/* POWER PC */
#if (defined(__GNUC__) && (defined(__powerpc__) || (defined(__ppc__))))
#define get_clockticks(val) \
{ \
    u_int32_t tbu0, tbu1, tbl; \
    do \
    { \
        __asm__ __volatile__ ("mftbu %0" : "=r"(tbu0)); \
        __asm__ __volatile__ ("mftb %0" : "=r"(tbl)); \
        __asm__ __volatile__ ("mftbu %0" : "=r"(tbu1)); \
    } while (tbu0 != tbu1); \
    val = ((UINT64)tbl) | (((UINT64)tbu0) << 32);  \
}
#else
#define get_clockticks(val)
#endif /* POWERPC || PPC */
#endif /* I386 || IA64 || AMD64 */
#endif /* WIN32 */

static INLINE double get_ticks_per_usec ()
{
    UINT64 start, end;
    get_clockticks(start);

#ifdef WIN32
    Sleep(1000);
#else
    sleep(1);
#endif
    get_clockticks(end);

    return (double)(end-start)/1e6;
}


#endif /* CPU_CLOCK_TICKS_H */
