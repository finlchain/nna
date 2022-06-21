/**
    @file mem.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/


#ifndef __MEM_H__
#define __MEM_H__

#ifdef __cplusplus
extern "C"
{
#endif

#define MEM_BLK_USE	    ENABLED // ENABLED DISABLED
#define MEM_BLK_DEBUG   ENABLED // ENABLED DISABLED
#define MEM_BLK_TEST    DISABLED // ENABLED DISABLED

#if (MEM_BLK_USE == ENABLED)
extern int32_t mem_blk_init(uint8_t *p_mblk, uint32_t size);
extern void *mem_malloc(uint8_t *p_mblk, uint32_t size);
extern void mem_free(uint8_t *p_mblk, void *p_alloc);
#if (MEM_BLK_DEBUG == ENABLED)
extern void mem_trace(uint8_t *p_mblk);
#endif // MEM_BLK_DEBUG

#if (MEM_BLK_TEST == ENABLED)
extern void mem_test(void);
#endif // MEM_BLK_TEST

#endif // MEM_BLK_USE

#ifdef __cplusplus
    }
#endif

#endif	// __MEM_H__

