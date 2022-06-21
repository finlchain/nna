/**
    @file tx_task_msg.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

LIST_T tx_task_list, tx_task_pool;
TASK_MSG_ITEM_T tx_task_items[TX_TASK_MSG_POOL_SIZE];

void tx_task_msg_init(void)
{
    DBG_PRINT(DBG_TIMER, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    
    task_msg_init(&tx_task_list, &tx_task_pool, TX_TASK_MSG_POOL_SIZE, tx_task_items);
}

void tx_task_msg_handler(void)
{
    TASK_MSG_ITEM_T *p_item;

    DBG_PRINT(DBG_CONS, DBG_NONE, (void *)"(%s)\n", __FUNCTION__);

    // Get the item from LIST
    p_item = task_get_msg(&tx_task_list);
    if (p_item)
    {
        // Process
        if (p_item->event == TX_TASK_MSG_EVENT_01)
        {
            DBG_PRINT(DBG_TX, DBG_NONE, (void *)"TX_TASK_MSG_EVENT_01\n");
        }
        else if (p_item->event == TX_TASK_MSG_EVENT_02)
        {
            DBG_PRINT(DBG_TX, DBG_NONE, (void *)"TX_TASK_MSG_EVENT_02\n");
        }

       // Return the list into POOL
        task_clr_msg(&tx_task_pool, &tx_task_list, p_item);
    }
}

