/**
    @file cons_task_msg.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

LIST_T cons_task_list, cons_task_pool;
TASK_MSG_ITEM_T cons_task_items[CONS_TASK_MSG_POOL_SIZE];

void fsdump_gen(void)
{
    P2P_CNTX_T *p_p2p_cntx = p2p_get_cntx();
    static uint64_t db_key = CONS_SET_SUBNET_ID(p_p2p_cntx->my_uniq_addr);
    static CONS_TX_INFO_T tx_info[CONS_TX_INFO_MAX];
    uint32_t cnt;

    DBG_PRINT(DBG_CONS, DBG_NONE, (void *)"(%s)\n", __FUNCTION__);

    for (cnt=0; cnt<CONS_TX_INFO_MAX; cnt++)
    {
        tx_info[cnt].db_key = db_key;
        
        openssl_sha256(tx_info[cnt].sc_hash, (uint8_t *)&tx_info[cnt].db_key, DB_KEY_SIZE);
        
        DBG_DUMP(DBG_CONS, DBG_NONE, (void *)"sc_hash", tx_info[cnt].sc_hash, HASH_SIZE);
        db_key++;
    }

#if (REDIS_SUB_TX == ENABLED)
    cons_send_tx(cnt, tx_info);
#endif // REDIS_SUB_TX

    //
    {
        static bool set_time = true;
        static struct timeval prvTime;
        struct timeval curTime;
        
        gettimeofday (&curTime, NULL);
        
        if (set_time)
        {
            prvTime.tv_sec = curTime.tv_sec;
            prvTime.tv_usec = curTime.tv_usec;
        }
        else
        {
            if (curTime.tv_sec > prvTime.tv_sec)
            {
                DBG_PRINT(DBG_CONS, DBG_INFO, (void *)"db_key[0] (0x%016llX) db_key[%d] (0x%016llX)\n", tx_info[0].db_key, cnt, tx_info[cnt].db_key);
                //check**
        
                prvTime.tv_sec = curTime.tv_sec;
                prvTime.tv_usec = curTime.tv_usec;
            }
        }
    }
}

void cons_task_msg_init(void)
{
    DBG_PRINT(DBG_CONS, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    
    task_msg_init(&cons_task_list, &cons_task_pool, CONS_TASK_MSG_POOL_SIZE, cons_task_items);
}

void cons_task_msg_handler(void)
{
    TASK_MSG_ITEM_T *p_item;

    DBG_PRINT(DBG_CONS, DBG_NONE, (void *)"(%s)\n", __FUNCTION__);

    // Get the item from LIST
    p_item = task_get_msg(&cons_task_list);
    if (p_item)
    {
        // Process
        if (p_item->event == CONS_TASK_MSG_EVENT_01)
        {
            DBG_PRINT(DBG_CONS, DBG_INFO, (void *)"CONS_TASK_MSG_EVENT_01\n");
        }
        else if (p_item->event == CONS_TASK_MSG_EVENT_02)
        {
            DBG_PRINT(DBG_CONS, DBG_INFO, (void *)"CONS_TASK_MSG_EVENT_02\n");
        }
        else if (p_item->event == CONS_TASK_MSG_EVENT_03)
        {
            DBG_PRINT(DBG_CONS, DBG_INFO, (void *)"CONS_TASK_MSG_EVENT_03\n");
        }
#if (CONS_TO_DB_TASK != ENABLED)
        else if (p_item->event == CONS_TASK_MSG_EVENT_10)
        {
            DBG_PRINT(DBG_CONS, DBG_INFO, (void *)"CONS_TASK_MSG_EVENT_10\n");

            cons_block_gen();
        }
#endif // CONS_TO_DB_TASK
        else if (p_item->event == CONS_TASK_MSG_EVENT_11)
        {
            DBG_PRINT(DBG_CONS, DBG_NONE, (void *)"CONS_TASK_MSG_EVENT_11\n");
            
            fsdump_gen();
        }
        else if (p_item->event == CONS_TASK_MSG_EVENT_13)
        {
            //
        }
        else if (p_item->event == CONS_TASK_MSG_EVENT_14)
        {
            //
        }

        // Return the list into POOL
        task_clr_msg(&cons_task_pool, &cons_task_list, p_item);
    }
}

