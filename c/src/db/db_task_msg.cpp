/**
    @file db_task_msg.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

LIST_T db_task_list, db_task_pool;
TASK_MSG_ITEM_T db_task_items[DB_TASK_MSG_POOL_SIZE];

void db_task_msg_init(void)
{
    DBG_PRINT(DBG_DB, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    
    task_msg_init(&db_task_list, &db_task_pool, DB_TASK_MSG_POOL_SIZE, db_task_items);
}

void db_task_msg_handler(void)
{
    TASK_MSG_ITEM_T *p_item;

    DBG_PRINT(DBG_CONS, DBG_NONE, (void *)"(%s)\n", __FUNCTION__);

    // Get the item from LIST
    p_item = task_get_msg(&db_task_list);
    if (p_item)
    {
        // Process
#if (CONS_TO_DB_TASK == ENABLED)
        if (p_item->event == DB_TASK_MSG_EVENT_01)
        {
            DB_TX_FIELD_T *p_tx_field;
            uint32_t cnt, idx;
            DBG_PRINT(DBG_DB, DBG_NONE, (void *)"DB_TASK_MSG_EVENT_01\n");

            ASSERT_M(p_item->len >= sizeof(DB_TX_FIELD_T));

            p_tx_field = (DB_TX_FIELD_T *)p_item->buf;

            cnt = (p_item->len / sizeof(DB_TX_FIELD_T));

            DBG_PRINT(DBG_DB, DBG_NONE, (void *)"Transaction len(%d), cnt(%d)\n", p_item->len, cnt);
            DBG_PRINT(DBG_DB, DBG_NONE, (void *)"3 blk_num (0x%016llX) Transaction last_db_key(0x%016llX)\n", p_tx_field[cnt-1].blk_num, p_tx_field[cnt-1].db_key);
            for (idx=0; idx<cnt; idx++)
            {
                db_tx_list_add((DB_TX_FIELD_T *)&p_tx_field[idx]);
            }
            //db_tx_list_remove();
            
            {
                CONS_TX_INFO_T *p_tx_info;
                p_tx_info = (CONS_TX_INFO_T *)MALLOC_M(sizeof(CONS_TX_INFO_T)*cnt);
                if (p_tx_info)
                {
                    for (idx=0; idx<cnt; idx++)
                    {
                        p_tx_info[idx].db_key = p_tx_field[idx].db_key;
                        MEMCPY_M(p_tx_info[idx].sc_hash, p_tx_field[idx].sc_hash, HASH_SIZE);
                    }
#if (REDIS_SUB_TX == ENABLED)
                    cons_send_tx_ack(SUCCESS_, p_tx_field->blk_num, cnt, p_tx_info);
#endif // REDIS_SUB_TX                    
                    FREE_M(p_tx_info);
                }
                else
                {
                    ASSERT_M(0);
                }
            }
        }
        else if (p_item->event == DB_TASK_MSG_EVENT_02)
        {
            DBG_PRINT(DBG_DB, DBG_NONE, (void *)"DB_TASK_MSG_EVENT_02\n");

            db_tx_list_remove();
        }
        else if (p_item->event == DB_TASK_MSG_EVENT_03)
        {
            DBG_PRINT(DBG_DB, DBG_WARN, (void *)"DB_TASK_MSG_EVENT_03 - len(%d)\n", p_item->len);

            db_tx_list_remove();
            cons_block_gen();
        }
        else if (p_item->event == DB_TASK_MSG_EVENT_04)
        {
            CONS_LIGHT_BLK_T *p_light_blk;

            ASSERT_M (p_item->len == sizeof(CONS_LIGHT_BLK_T));
            
            p_light_blk = (CONS_LIGHT_BLK_T *)&p_item->buf[0];

            // db_tx_list_remove();
            //DBG_PRINT(DBG_DB, DBG_NONE, (void *)"blk_num(0x%016llX) blk_tx_count(%d) my_tx_count(%d)\n", p_light_blk->blk_num, p_light_blk->tx_cnt, DB_SELECT_COUNT_F_BLK_TXS_W_BN(p_light_blk->blk_num));
            DB_INSERT_T_BLK_CONTENTS(p_light_blk);
        }
        else if (p_item->event == DB_TASK_MSG_EVENT_05)
        {
            //
        }
#endif // CONS_TO_DB_TASK

        // Return the list into POOL
        task_clr_msg(&db_task_pool, &db_task_list, p_item);
    }
}

