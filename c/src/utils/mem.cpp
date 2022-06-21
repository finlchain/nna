/**
    @file mem.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

#define MEM_BLK_SIZE_MAX    0x7FFFFFFC // Multiple of 4
#define MEM_BLK_ALLOC_BIT   0x80000000
#define MEM_BLK_SIZE_UNIT   0x4

#define MEM_BLK_FREGMENT    0x3
#define MEM_BLK_HDR         0
#define MEM_BLK_DATA        1

pthread_mutex_t mem_mutex = PTHREAD_MUTEX_INITIALIZER;

#if (MEM_BLK_USE == ENABLED)
int32_t mem_blk_init(uint8_t *p_mblk, uint32_t size)
{
	uint32_t *p_mblk_size;

	ASSERT_M(size >= (MEM_BLK_SIZE_UNIT * 2));

    pthread_mutex_lock (&mem_mutex);
    
	p_mblk_size = (uint32_t *)p_mblk;

	p_mblk_size[MEM_BLK_HDR] = (size & MEM_BLK_SIZE_MAX);
	p_mblk_size[MEM_BLK_DATA] = ((size & MEM_BLK_SIZE_MAX) - MEM_BLK_SIZE_UNIT);

    pthread_mutex_unlock (&mem_mutex);
    
	return (SUCCESS_);
}

void *mem_malloc(uint8_t *p_mblk, uint32_t size)
{
	uint32_t *p_cur_size;
    uint32_t tot_size;
	uint32_t stack_size;

    pthread_mutex_lock (&mem_mutex);
    
    if (size & MEM_BLK_FREGMENT)
    {
        size &= MEM_BLK_SIZE_MAX;
        size += MEM_BLK_SIZE_UNIT;
    }

    stack_size = MEM_BLK_SIZE_UNIT;
	size += stack_size;

    ASSERT_M((size % MEM_BLK_SIZE_UNIT) == 0);

    tot_size = *(uint32_t *)p_mblk;
	if((size == 0) || (size > tot_size))
	{
        pthread_mutex_unlock (&mem_mutex);
        
        return (NULL);
	}
    
	do
	{
        ASSERT_M((stack_size % MEM_BLK_SIZE_UNIT) == 0);
        
		p_cur_size = (uint32_t *)&p_mblk[stack_size];

		if((p_cur_size[MEM_BLK_HDR] & MEM_BLK_SIZE_MAX) >= size && !(p_cur_size[MEM_BLK_HDR] & MEM_BLK_ALLOC_BIT))
		{
			if(p_cur_size[MEM_BLK_HDR] > (size + MEM_BLK_SIZE_UNIT))	// Split mBlk if a mblk is bigger than requsted size plus two ...
			{
				uint32_t *p_nxt_size;
                uint8_t *p_cur;

                p_cur = (uint8_t *)p_cur_size;
				p_nxt_size = (uint32_t *)&p_cur[size];
				p_nxt_size[MEM_BLK_HDR] = (p_cur_size[MEM_BLK_HDR] & MEM_BLK_SIZE_MAX) - size;

				p_cur_size[MEM_BLK_HDR] = (size | MEM_BLK_ALLOC_BIT);
			}
			else
			{
				p_cur_size[MEM_BLK_HDR] = (p_cur_size[MEM_BLK_HDR] | MEM_BLK_ALLOC_BIT);
			}

            pthread_mutex_unlock (&mem_mutex);
            
			return ((void *)&p_cur_size[MEM_BLK_DATA]);
		}

		stack_size += (p_cur_size[MEM_BLK_HDR] & MEM_BLK_SIZE_MAX);
	}while(stack_size < tot_size);

    pthread_mutex_unlock (&mem_mutex);
    
	return (NULL);
}

void mem_free(uint8_t *p_mblk, void *p_alloc)
{
	uint32_t *p_alloc_size, *p_cur_size, *p_prv_size;
	uint32_t stack_size;
    uint32_t tot_size;

    pthread_mutex_lock (&mem_mutex);
    
	p_alloc_size = (uint32_t *)((uint8_t *)p_alloc - MEM_BLK_SIZE_UNIT);

    p_prv_size = NULL;
    stack_size = MEM_BLK_SIZE_UNIT;
    tot_size = *(uint32_t *)p_mblk;
    
	do
	{
		p_cur_size = (uint32_t *)&p_mblk[stack_size];

		if((p_cur_size == p_alloc_size) && (p_cur_size[MEM_BLK_HDR] & MEM_BLK_ALLOC_BIT))
		{
			p_cur_size[MEM_BLK_HDR] &= MEM_BLK_SIZE_MAX;

			// Check previous memory block...
			if((p_prv_size != NULL) && (!(p_prv_size[MEM_BLK_HDR] & MEM_BLK_ALLOC_BIT)))
			{
				p_prv_size[MEM_BLK_HDR] += p_cur_size[MEM_BLK_HDR];	// Prev mBlk + Curr mBlk ...
			}
			else
			{
				p_prv_size = p_cur_size;
			}

			// Check next memory block...
			p_cur_size = (uint32_t *)((uint8_t *)p_cur_size + p_cur_size[MEM_BLK_HDR]);
			if(!(p_cur_size[MEM_BLK_HDR] & MEM_BLK_ALLOC_BIT))
			{
				p_prv_size[MEM_BLK_HDR] += p_cur_size[MEM_BLK_HDR];	// (Prev mBlk +) Curr mBlk + Next mBlk ...
			}

            pthread_mutex_unlock (&mem_mutex);
            
			return;
		}

		p_prv_size = p_cur_size;
		stack_size += (p_cur_size[MEM_BLK_HDR] & MEM_BLK_SIZE_MAX);
	}while(stack_size < tot_size);

    pthread_mutex_unlock (&mem_mutex);
}

#if (MEM_BLK_DEBUG == ENABLED)
void mem_trace(uint8_t *p_mblk)
{
	uint32_t *p_cur_size;	
	uint32_t stack_size;
    uint32_t tot_size;

    pthread_mutex_lock (&mem_mutex);
    
    stack_size = MEM_BLK_SIZE_UNIT;
    tot_size = *(uint32_t *)p_mblk;

	do
	{
		p_cur_size = (uint32_t *)&p_mblk[stack_size];

        DBG_PRINT (DBG_UTIL, DBG_INFO, (void *)"Addr(%p) : Len(%d), Used(%d)\n", 
                    p_cur_size, 
                    (p_cur_size[MEM_BLK_HDR] & MEM_BLK_SIZE_MAX), 
                    (p_cur_size[MEM_BLK_HDR] & MEM_BLK_ALLOC_BIT) ? true : false);

		stack_size += (*p_cur_size & MEM_BLK_SIZE_MAX);

	}while(stack_size < tot_size);

    pthread_mutex_unlock (&mem_mutex);
}
#endif // MEM_BLK_DEBUG

#if (MEM_BLK_TEST == ENABLED)
extern void malloc_trace(void);

void mem_test(void)
{
    uint8_t *p_mem_test_1, *p_mem_test_2, *p_mem_test_3, *p_mem_test_4;

    DBG_PRINT (DBG_UTIL, DBG_INFO, (void *)"(%s) 1\n", __FUNCTION__);
    malloc_trace();
    p_mem_test_1 = (uint8_t *)MALLOC_M(1500);

    DBG_PRINT (DBG_UTIL, DBG_INFO, (void *)"(%s) 2\n", __FUNCTION__);
    malloc_trace();
    p_mem_test_2 = (uint8_t *)MALLOC_M(1000);
    DBG_PRINT (DBG_UTIL, DBG_INFO, (void *)"(%s) 3\n", __FUNCTION__);
    malloc_trace();
    p_mem_test_3 = (uint8_t *)MALLOC_M(2100);
    DBG_PRINT (DBG_UTIL, DBG_INFO, (void *)"(%s) 4\n", __FUNCTION__);
    malloc_trace();
    p_mem_test_4 = (uint8_t *)MALLOC_M(3500);
    DBG_PRINT (DBG_UTIL, DBG_INFO, (void *)"(%s) 5\n", __FUNCTION__);
    malloc_trace();

    FREE_M(p_mem_test_1);
    DBG_PRINT (DBG_UTIL, DBG_INFO, (void *)"(%s) 6\n", __FUNCTION__);
    malloc_trace();
    FREE_M(p_mem_test_3);
    DBG_PRINT (DBG_UTIL, DBG_INFO, (void *)"(%s) 7\n", __FUNCTION__);
    malloc_trace();
    FREE_M(p_mem_test_4);
    DBG_PRINT (DBG_UTIL, DBG_INFO, (void *)"(%s) 8\n", __FUNCTION__);
    malloc_trace();
    FREE_M(p_mem_test_2);
    DBG_PRINT (DBG_UTIL, DBG_INFO, (void *)"(%s) 9\n", __FUNCTION__);
    malloc_trace();
}
#endif // MEM_BLK_TEST

#endif // MEM_BLK_USE

