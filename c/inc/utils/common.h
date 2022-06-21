/**
    @file common.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#ifndef __COMMON_H__
#define __COMMON_H__

#ifdef __cplusplus
extern "C"
{
#endif

#define BYTE_8 sizeof(uint64_t)
#define BYTE_4 sizeof(uint32_t)
#define BYTE_2 sizeof(uint16_t)
#define BYTE_1 sizeof(uint8_t)

#ifndef MAX
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#endif

#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

#ifndef ABS
#define ABS(a) ((a) < (0) ? (-a) : (a))
#endif

#ifndef ARRAYSIZE
#define ARRAYSIZE(a) (sizeof(a) / sizeof(a[0]))
#endif

#ifndef IS_EQUAL
#define IS_EQUAL(a,b) ((a) == (b) ? true : false)
#endif

#ifndef IS_REMAINDER
#define IS_REMAINDER(a,b) ((a) % (b) ? true : false)
#endif

#ifndef IS_CONDITION
#define IS_CONDITION(a) ((a) ? true : false)
#endif

#ifndef FLOOR // 
#define FLOOR(a,b) ((a) - ((a) % (b)))
#endif

#ifndef CEIL // 
#define CEIL(a,b) ((a) % (b) ? ((a) - ((a) % (b)) + (b)) : (a))
#endif

#ifndef ROUND // 
#define ROUND(a,b)
#endif

#ifndef ROUNDF_UP // 
#define ROUNDF_UP(a) (floor((a)+0.5))
#endif

#ifndef ROUNDF_DOWN // 
#define ROUNDF_DOWN(a) (floor(a))
#endif

#ifndef BIT_SHIFT_L // 
#define BIT_SHIFT_L(a,b) ((a) << (b))
#endif


#ifndef NXT_IDX //
#define NXT_IDX(a,b) ( ((a) + 1) % (b))
#endif

#ifndef PRV_IDX //
#define PRV_IDX(a,b) ( (a) == 0 ? (b) - 1 : ( ((a) - 1) % (b)) )
#endif 

#define ASSERT_M(V) \
        {\
            if(!IS_CONDITION(V)) {\
                DBG_PRINT(DBG_UTIL, DBG_ERROR, (void *)"file(%s) func(%s) line(%d)\n", __FILE__, __FUNCTION__, __LINE__);\
            }\
            assert(V);\
        }

#define MEMCPY_M memcpy
#define MEMCPY_REV reverse_memcpy_m
#define MEMCPY_REV2 reverse_inplace_m
#define MEMSET_M memset
#define MEMCMP_M memcmp
#define MEMMOVE_M memmove

typedef struct 
{
    uint16_t u16_1;
    uint16_t u16_2;
    uint16_t u16_3;
    uint16_t u16_4;
} U16x4_T;

typedef struct 
{
    uint32_t u32_1;
    uint32_t u32_2;
} U32x2_T;

typedef union {
    uint64_t u64;
    U16x4_T u16;
    U32x2_T u32;
    uint8_t u8[BYTE_8];
} U64_U;

// In 32-bit mode, most likely long is 32 bits and long long is 64 bits. In 64-bit mode, both are probably 64 bits.
// In 32-bit mode, the compiler (more precisely the <stdint.h> header) defines uint64_t as unsigned long long, because unsigned long isn't wide enough.
// In 64-bit mode, it defines uint64_t as unsigned long.
typedef unsigned long long uintll_t; // = uint64_t

extern void *malloc_x (uint32_t s);
extern void *free_x (void *p);
extern void reverse_memcpy_m (void *p_dst, const void *p_src, uint32_t n);
extern void reverse_inplace_m (void *p_data, uint32_t n);
extern void xor_m(void *p_dst, const void *p_src_1, const void *p_src_2, uint32_t n);

extern int64_t a2i_64_m(const char *s);

//
inline void *alloc_trace(int size, const char *file, const char *func, int line)
{
    void *p_mem;

    p_mem = malloc_x((uint32_t)size);
    
    get_current_rss_monitor(DBG_NONE, (char *)func);
    DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"malloc line(%d) size(%d)\n", line, (size));
    DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"malloc addr(0x%016llX)\n", (unsigned long long)(p_mem));

    return (p_mem);
}

#define MALLOC_M(S) alloc_trace(S, __FILE__, __FUNCTION__, __LINE__);
#define FREE_M(M) \
        {\
            if (M) {\
                DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"mfree addr(0x%016llX)\n", (unsigned long long)(M)); \
                free_x(M);\
                (M) = NULL;\
                get_current_rss_monitor(DBG_NONE, (char *)__FUNCTION__);\
                DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"free line(%d)\n", __LINE__);\
            }\
        }

#define MALLOC_MEMCPY_M(D,S) \
        {\
            int __tmp_size = strlen(S);\
            D = (char *)MALLOC_M(__tmp_size+1);\
            get_current_rss_monitor(DBG_NONE, (char *)__FUNCTION__);\
            ASSERT_M(D);\
            MEMCPY_M(D,S,__tmp_size);\
            D[__tmp_size] = '\0';\
        }

#define CALLOC_M calloc
#define STRCMP_M strcmp
#define STRLEN_M strlen
#define STRSTR_M strstr
#define STRCPY_M strcpy
#define ATOI_M a2i_64_m
#define ATOI_64_M a2i_64_m

#define SPRINTF_M sprintf

#ifdef __cplusplus
}
#endif

#endif /* __COMMON_H__ */

