/**
    @file db_redis_task_msg.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

LIST_T db_redis_task_list, db_redis_task_pool;
TASK_MSG_ITEM_T db_redis_task_items[DB_REDIS_TASK_MSG_POOL_SIZE];

void db_redis_task_msg_init(void)
{
    DBG_PRINT(DBG_DB, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    
    task_msg_init(&db_redis_task_list, &db_redis_task_pool, DB_REDIS_TASK_MSG_POOL_SIZE, db_redis_task_items);
}

void db_redis_task_msg_handler(void)
{
    TASK_MSG_ITEM_T *p_item;

    DBG_PRINT(DBG_DB, DBG_NONE, (void *)"(%s)\n", __FUNCTION__);

    // Get the item from LIST
    p_item = task_get_msg(&db_redis_task_list);
    if (p_item)
    {
        // Process
        if (p_item->event == DB_REDIS_TASK_MSG_EVENT_01)
        {
#if (REDIS_SUB_TX == ENABLED)
            CONS_TX_INFO_T *p_tx_info;
            uint32_t tx_info_cnt;

            DBG_PRINT(DBG_DB, DBG_NONE, (void *)"DB_REDIS_TASK_MSG_EVENT_01\n");
            
            ASSERT_M (!(p_item->len % sizeof(CONS_TX_INFO_T)));
            
            tx_info_cnt = p_item->len / sizeof(CONS_TX_INFO_T);
            p_tx_info = (CONS_TX_INFO_T *)&p_item->buf[0];
            
            cons_send_tx(tx_info_cnt, p_tx_info);
#endif // REDIS_SUB_TX
        }
        else if (p_item->event == DB_REDIS_TASK_MSG_EVENT_02)
        {
#if (REDIS_SUB_TX == ENABLED)
            CONS_TX_ACK_INFO_T *p_tx_ack;

            DBG_PRINT(DBG_DB, DBG_NONE, (void *)"DB_REDIS_TASK_MSG_EVENT_02\n");
            
            p_tx_ack = (CONS_TX_ACK_INFO_T *)&p_item->buf[0];
            redis_pub_tx_ack(p_tx_ack);
#endif // REDIS_SUB_TX
        }
        else if (p_item->event == DB_REDIS_TASK_MSG_EVENT_03)
        {
            CONS_LIGHT_BLK_T *p_light_blk;

            p_light_blk = (CONS_LIGHT_BLK_T *)&p_item->buf[0];
            redis_pub_blk_noti(p_light_blk);
        }
        else if (p_item->event == DB_REDIS_TASK_MSG_EVENT_04)
        {
            redis_pub_ctrl_acks((const char *)&p_item->buf[0]);
        }

        // Return the list into POOL
        task_clr_msg(&db_redis_task_pool, &db_redis_task_list, p_item);
    }
}

