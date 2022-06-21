/**
    @file task_msg.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

pthread_mutex_t task_mutex = PTHREAD_MUTEX_INITIALIZER;

int32_t task_msg_init(LIST_T *p_list, LIST_T *p_pool, uint32_t pool_size, TASK_MSG_ITEM_T *p_item)
{
    uint32_t cnt;

    DBG_PRINT(DBG_TASK, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    pthread_mutex_lock (&task_mutex);
    
    list_init (p_list);
    list_init (p_pool);

    for( cnt=0; cnt<pool_size; cnt++ )\
    {
#if (TASK_MSG_STATIC_BUF == DISABLED)
        p_item[cnt].buf = NULL;
#endif // TASK_MSG_STATIC_BUF
        list_insert (p_pool, &p_item[cnt].link);
    }
    
    pthread_mutex_unlock (&task_mutex);

    DBG_PRINT(DBG_TASK, DBG_INFO, (void *)"pool(0x%016llX) p_pool->num_items(%d)\n", (uint64_t)p_pool, p_pool->num_items);
    DBG_PRINT(DBG_TASK, DBG_INFO, (void *)"list(0x%016llX) p_list->num_items(%d)\n", (uint64_t)p_list, p_list->num_items);

    return (SUCCESS_);
}

int32_t task_send_msg(LIST_T *p_pool, LIST_T *p_list, uint8_t *p_buf, int32_t len, uint32_t alloced, uint32_t event)
{
    TASK_MSG_ITEM_T *p_item;
    int32_t temp;
    
    DBG_PRINT(DBG_TASK, DBG_NONE, (void *)"(%s)\n", __FUNCTION__);

    pthread_mutex_lock (&task_mutex);
    
    if (list_is_empty(p_pool))
    {
        pthread_mutex_unlock (&task_mutex);
        DBG_PRINT(DBG_TASK, DBG_ERROR, (void *)"(%s) Error - Task Pool is Empty, pool(%d), list(%d)\n", __FUNCTION__, p_pool->num_items, p_list->num_items);
        ASSERT_M(0);
        return (ERROR_);
    }
#if (TASK_MSG_STATIC_BUF == ENABLED)
    if (len > TASK_BUF_SIZE)
    {
        pthread_mutex_unlock (&task_mutex);
        DBG_PRINT(DBG_TASK, DBG_ERROR, (void *)"(%s) Error - Task BUF Size, TASK_BUF_SIZE(%d), len(%d)\n", __FUNCTION__, TASK_BUF_SIZE, len);
        ASSERT_M(0);
        return (ERROR_);
    }
#endif // TASK_MSG_STATIC_BUF
    p_item = (TASK_MSG_ITEM_T *)list_remove(p_pool);
    
    ASSERT_M(p_item);

    if(!p_item)
    {
        return (ERROR_);
    }

    p_item->len = len;
    if (p_item->len)
    {
#if (TASK_MSG_STATIC_BUF == DISABLED)
        if (alloced)
        {
            ASSERT_M(p_buf);
            p_item->buf = p_buf;
        }
        else
        {
            if (p_item->len)
            {
                p_item->buf = (uint8_t *)MALLOC_M(p_item->len);
                MEMCPY_M(p_item->buf, p_buf, p_item->len);
            }
        }
#else
        MEMCPY_M(p_item->buf, p_buf, p_item->len);
#endif // TASK_MSG_STATIC_BUF
    }

    p_item->event = event;

    list_insert(p_list, &p_item->link);

    temp = (p_pool->num_items + p_list->num_items) % 10;

    pthread_mutex_unlock (&task_mutex);

    if(temp)
    {
        DBG_PRINT(DBG_TASK, DBG_NONE, (void *)"(%s) pool(0x%016llX) p_pool->num_items(%d)\n", __FUNCTION__, (uint64_t)p_pool, p_pool->num_items);
        DBG_PRINT(DBG_TASK, DBG_NONE, (void *)"(%s) list(0x%016llX) p_list->num_items(%d) event(%d)\n", __FUNCTION__, (uint64_t)p_list, p_list->num_items, p_item->event);
        DBG_PRINT(DBG_TASK, DBG_NONE, (void *)"(%s) mod val (%d)\n", __FUNCTION__, temp);

//        ASSERT_M(0);
    }

    return (SUCCESS_);
}

TASK_MSG_ITEM_T *task_get_msg(LIST_T *p_list)
{
    TASK_MSG_ITEM_T *p_item = NULL;

    DBG_PRINT(DBG_TASK, DBG_NONE, (void *)"(%s)\n", __FUNCTION__);

    pthread_mutex_lock (&task_mutex);
    
    if (!list_is_empty(p_list))
    {
        p_item = (TASK_MSG_ITEM_T *)list_remove(p_list);
    }
    
    pthread_mutex_unlock (&task_mutex);

    if (p_item)
    {
        DBG_PRINT(DBG_TASK, DBG_NONE, (void *)"(%s) list(0x%016llX) p_list->num_items(%d) event(%d)\n", __FUNCTION__, (uint64_t)p_list, p_list->num_items, p_item->event);
    }
    
    return (p_item);
}

void task_init_item(TASK_MSG_ITEM_T *p_item)
{
#if (TASK_MSG_STATIC_BUF == DISABLED)
    FREE_M(p_item->buf);
#endif // TASK_MSG_STATIC_BUF
    p_item->event = 0;
}

void task_clr_msg(LIST_T *p_pool, LIST_T *p_list, TASK_MSG_ITEM_T *p_item)
{
    int32_t temp;

    task_init_item(p_item);

    pthread_mutex_lock (&task_mutex);
    
    list_insert(p_pool, &p_item->link);
    temp = (p_pool->num_items + p_list->num_items) % 10;
    
    pthread_mutex_unlock (&task_mutex);

    DBG_PRINT(DBG_TASK, DBG_NONE, (void *)"(%s) pool(0x%016llX) p_pool->num_items(%d) event(%d)\n", __FUNCTION__, (uint64_t)p_pool, p_pool->num_items, p_item->event);

    if(temp)
    {
        DBG_PRINT(DBG_TASK, DBG_INFO, (void *)"(%s) pool(0x%016llX) p_pool->num_items(%d)\n", __FUNCTION__, (uint64_t)p_pool, p_pool->num_items);
        DBG_PRINT(DBG_TASK, DBG_INFO, (void *)"(%s) list(0x%016llX) p_list->num_items(%d) event(%d)\n", __FUNCTION__, (uint64_t)p_list, p_list->num_items, p_item->event);
        DBG_PRINT(DBG_TASK, DBG_INFO, (void *)"(%s) mod val (%d)\n", temp);

        ASSERT_M(0);
    }
}

