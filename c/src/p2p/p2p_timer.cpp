/**
    @file p2p_timer.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

#if (P2P_TEST == ENABLED)
int32_t p2p_timer_client_data(int32_t in_val_1)
{
    int32_t ret;
    
    ret = task_send_msg(&p2p_task_pool, &p2p_task_list, NULL, 0, false, P2P_TASK_MSG_EVENT_01);
    if (ret == ERROR_)
    {
        ASSERT_M(0);
    }

    return (ret);
}
#endif // P2P_TEST

int32_t p2p_timer_sock_conn(int32_t in_val_1)
{
    int32_t ret;
    
    // Don't process anyting on this function.
    // Just notify time expireation using message event.
    ret = task_send_msg(&p2p_task_pool, &p2p_task_list, NULL, 0, false, P2P_TASK_MSG_EVENT_02);
    if (ret == ERROR_)
    {
        ASSERT_M(0);
    }
    
    return (ret);
}

int32_t p2p_timer_sock_conn_with_idx(int32_t in_val_1)
{
    int32_t ret;
    
    // Don't process anyting on this function.
    // Just notify time expireation using message event.
    
    ret = task_send_msg(&p2p_task_pool, &p2p_task_list, (uint8_t *)&in_val_1, BYTE_4, false, P2P_TASK_MSG_EVENT_03);
    if (ret == ERROR_)
    {
        ASSERT_M(0);
    }
    
    return (ret);
}

void p2p_timer_run (void)
{
    DBG_PRINT(DBG_TIMER, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

#if (P2P_TEST == ENABLED)
    P2P_CNTX_T *p_p2p_cntx = p2p_get_cntx();

//    if (p_p2p_cntx->my_node_info.node_rule & P2P_NODE_RULE_NN)
     if (0)
     {
        bool one_shot = false;
        
#if (P2P_TEST_PINGPONG == ENABLED)
        one_shot = true;
#endif // P2P_TEST_PINGPONG

        timer_sw_reg((uint8_t *)"p2p_data", one_shot, 1000000, 0, p2p_timer_client_data, 0);
    }
#endif // P2P_TEST
}

