/**
    @file common.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief common functionality
*/

#include "global.h"

#if (MEM_BLK_USE == ENABLED)
#define MEM_BLK_SIZE 1600000
uint8_t g_mem_blk[MEM_BLK_SIZE];
#endif // MEM_BLK_USE

#if (MEM_BLK_USE == ENABLED)
void malloc_init(void)
{
    mem_blk_init(g_mem_blk, MEM_BLK_SIZE);
}

#if (MEM_BLK_DEBUG == ENABLED)
void malloc_trace(void)
{
    mem_trace(g_mem_blk);
}
#endif // MEM_BLK_DEBUG 

#endif // MEM_BLK_USE
void *malloc_x (uint32_t s)
{
    void *p;
    
#if (MEM_BLK_USE == ENABLED)
    p = mem_malloc(g_mem_blk, s);
#else
    p = malloc(s);
#endif // MEM_BLK_USE

    if (p)
    {
        memset(p, 0x00, s);
    }
    
    DBG_PRINT (DBG_UTIL, DBG_END, (void *)"(%s) [0x%p]\n", __FUNCTION__, p);

    return p;
}

void *free_x (void *p)
{
    if (p)
    {
        DBG_PRINT (DBG_UTIL, DBG_END, (void *)"(%s) [0x%p]\n", __FUNCTION__, p);

#if (MEM_BLK_USE == ENABLED)
        mem_free(g_mem_blk, p);
#else
        free(p);
#endif // MEM_BLK_USE

        p = NULL;
    }

    return (NULL);
}

void reverse_memcpy_m (void *p_dst, const void *p_src, uint32_t n)
{
    uint32_t i;
    uint8_t *dst = (uint8_t *)p_dst, *src = (uint8_t *)p_src;

    for (i=0; i < n; ++i)
        dst[n-1-i] = src[i];
}

void reverse_inplace_m (void *p_data, uint32_t n)
{
    uint32_t i;
    uint8_t *data = (uint8_t *)p_data;
    uint8_t tmp;

    for (i=0; i < n/2; ++i) {
        tmp = data[i];
        data[i] = data[n - 1 - i];
        data[n - 1 - i] = tmp;
    }
}

void xor_m(void *p_dst, const void *p_src_1, const void *p_src_2, uint32_t n)
{
    uint32_t i;
    uint8_t *dst = (uint8_t *)p_dst, *src_1 = (uint8_t *)p_src_1, *src_2 = (uint8_t *)p_src_2;

    for (i=0; i < n; i++)
        dst[i] = src_1[i] ^ src_2[i];
}

int64_t a2i_64_m(const char *s)
{
    int64_t sign = 1;
    int64_t num = 0;
    
    if(*s == '-')
    {
        sign = -1;
        s++;
    }
    
    while(*s)
    {
        num=((*s)-'0')+num*10;
        s++;   
    }
    return num*sign;
}

