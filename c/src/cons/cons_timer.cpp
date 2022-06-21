/**
    @file cons_timer.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

int32_t cons_fsdump_temp(int32_t in_val_1)
{
    int32_t ret;
    
    ret = task_send_msg(&cons_task_pool, &cons_task_list, NULL, 0, false, CONS_TASK_MSG_EVENT_11);
    if (ret == ERROR_)
    {
        ASSERT_M(0);
    }
    
    return (ret);
}

int32_t cons_timer_tx_stop(int32_t in_val_1)
{
    int32_t ret;

    // block gen 
    ret = cons_block_gen_msg();
    if (ret == ERROR_)
    {
        ASSERT_M(0);
    }
    
    return (ret);
}


void cons_timer_run (void)
{
    DBG_PRINT(DBG_TIMER, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
}

