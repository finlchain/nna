/**
    @file db_timer.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

int32_t db_timer_insert_tx(int32_t in_val_1)
{
    int32_t ret;
    
    // Don't process anyting on this function.
    // Just notify time expireation using message event.

    ret = task_send_msg(&db_task_pool, &db_task_list, NULL, 0, false, DB_TASK_MSG_EVENT_02);
    if (ret == ERROR_)
    {
        ASSERT_M(0);
    }

    return (SUCCESS_);
}

void db_timer_run (void)
{
    DBG_PRINT(DBG_TIMER, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    
    timer_sw_reg((uint8_t *)"db_tm", false, 50000, 0, db_timer_insert_tx, 0);
}

