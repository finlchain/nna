/**
    @file cons_rr.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

void cons_rr_net_init(void)
{
    CONS_CNTX_T *p_cons_cntx = cons_get_cntx();
    P2P_CNTX_T *p_p2p_cntx = p2p_get_cntx();
    uint32_t idx;
    CONS_TIER_T *p_tier;

    DBG_PRINT (DBG_CONS, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    if (!(p_p2p_cntx->my_node_info.node_rule & P2P_NODE_RULE_NN))
    {
        DBG_PRINT (DBG_CONS, DBG_ERROR, (void *)"This node is not NN.\n");
        return;
    }

    p_tier = &p_cons_cntx->net.tier[CONS_TIER_0];

    p_tier->blk_gen_interval = 0;
    p_tier->blk_gen_sub_intrvl = 0;
    p_tier->blk_gen_round_cnt = 0;
    p_tier->blk_gen_start_time = 0;
    p_tier->blk_gen_start_block = BLK_NUM_INIT_VAL;
    p_tier->blk_gen_time = 0;
    p_tier->blk_gen_stop = CONS_BLK_GEN_STOP_DISABLED;
    
    for (idx=0; idx<p_tier->nn_gen_seq.total_nn; idx++)
    {
        p_tier->nn_gen_seq.root[idx].actived = false;
        p_tier->nn_gen_seq.root[idx].nn_p2p_addr = P2P_NULL_ADDR;
        
        p_tier->nn_gen_seq.root[idx].subnet.proto_type = 0;
        p_tier->nn_gen_seq.root[idx].subnet.ip = 0;
        p_tier->nn_gen_seq.root[idx].subnet.port = 0;
        p_tier->nn_gen_seq.root[idx].subnet.sockfd = -1;

        p_tier->blk_num   = 0;
        p_tier->blk_num  += 0;

        p_tier->nn_gen_seq.my_root_nn_idx = 0;
        p_tier->nn_gen_seq.my_next_nn_idx = 0;
    }
    
    p_tier->nn_gen_seq.total_nn = 0;

    p_cons_cntx->net.tier_num = 0;
}

void cons_rr_net_set_next_nn(void)
{
#if (TCP_SVR_CNNCT == ENABLED)
    CONS_CNTX_T *p_cons_cntx = cons_get_cntx();
    CONS_TIER_T *p_tier;

    uint32_t next_nn_idx;

    DBG_PRINT (DBG_CONS, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    
    p_tier = &p_cons_cntx->net.tier[CONS_TIER_0];

    next_nn_idx = p_tier->nn_gen_seq.my_next_nn_idx;

    DBG_PRINT (DBG_CONS, DBG_INFO, (void *)"my_root_nn_idx(%d) my_next_nn_idx(%d)\n", p_tier->nn_gen_seq.my_root_nn_idx, p_tier->nn_gen_seq.my_next_nn_idx);

    if (p_tier->nn_gen_seq.root[next_nn_idx].subnet.proto_type == CONS_TCP_TYPE)
    {
        DBG_PRINT (DBG_CONS, DBG_INFO, (void *)"NEXT NN[%d] (0x%016llX)\n", next_nn_idx, p_tier->nn_gen_seq.root[next_nn_idx].nn_p2p_addr);
        DBG_PRINT (DBG_CONS, DBG_INFO, (void *)"NEXT NN[%d] SUBNET(%s) IP(0x%08X) PORT(%d)\n", next_nn_idx,
                                (p_tier->nn_gen_seq.root[next_nn_idx].subnet.proto_type == CONS_TCP_TYPE)?"TCP":"UDP",
                                p_tier->nn_gen_seq.root[next_nn_idx].subnet.ip, 
                                p_tier->nn_gen_seq.root[next_nn_idx].subnet.port);

        if (p_tier->nn_gen_seq.my_root_nn_idx != p_tier->nn_gen_seq.my_next_nn_idx)
        {
            sock_open_tcp_client_with_reinit(p2p_sock_cntx(), TCP_CLI_1, 
                        NULL, p_tier->nn_gen_seq.root[next_nn_idx].subnet.ip, 
                        p_tier->nn_gen_seq.root[next_nn_idx].subnet.port);
        }
    }
#endif // TCP_SVR_CNNCT
}

void cons_rr_net_set_blk_num(void)
{
    CONS_CNTX_T *p_cons_cntx = cons_get_cntx();
    CONS_TIER_T *p_tier;
#if (CONS_USE_SUBNET_ID == ENABLED)
    P2P_CNTX_T *p_p2p_cntx = p2p_get_cntx();
#endif // CONS_USE_SUBNET_ID

    DBG_PRINT (DBG_CONS, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    p_tier = &p_cons_cntx->net.tier[CONS_TIER_0];

    // Update Block Number
    p_tier->blk_num   = p_tier->nn_gen_seq.my_root_nn_idx;
    p_tier->blk_num  += p_tier->blk_gen_start_block;
#if (CONS_USE_SUBNET_ID == ENABLED)
    p_tier->blk_num  |= CONS_SET_SUBNET_ID(p_p2p_cntx->my_uniq_addr);
#endif // CONS_USE_SUBNET_ID
    DBG_PRINT (DBG_CONS, DBG_INFO, (void *)"blk_num(0x%016llX)\n", p_tier->blk_num);
}

int32_t cons_tx_stop(void)
{
    CONS_CNTX_T *p_cons_cntx = cons_get_cntx();
    CONS_TIER_T *p_tier;

    DBG_PRINT (DBG_CONS, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    p_tier = &p_cons_cntx->net.tier[CONS_TIER_0];
    
    if (p_tier->blk_gen_interval)
    {
        do
        {
            uint64_t curr_utc_ms;
            uint32_t gen_interval = 0; // UTC time in usec
            uint64_t gen_time = 0;

            curr_utc_ms = util_curtime_ms();

            // Genesis Block
            if (curr_utc_ms < p_tier->blk_gen_start_time)
            {
                //gen_interval = 0;
                gen_time = p_tier->blk_gen_start_time * 1000;
            }
            else
            {
#if 1
                uint64_t blk_rr_interval = 0;

                DBG_PRINT(DBG_CONS, DBG_INFO, (void *)"curr_utc_ms(%llu), blk_gen_time(%llu).\n", curr_utc_ms, p_tier->blk_gen_time);

                if (p_tier->blk_gen_time)
                {
                    ASSERT_M(p_tier->blk_gen_time <= curr_utc_ms);
                    
                    blk_rr_interval = curr_utc_ms - p_tier->blk_gen_time;
                }

                if (blk_rr_interval < p_tier->blk_gen_interval)
                {
                    uint32_t cur_blk_gen_interval;

                    cur_blk_gen_interval = p_tier->blk_gen_interval - (uint32_t)blk_rr_interval;
                    gen_interval = cur_blk_gen_interval * 1000;
                }
                else
                {
                    DBG_PRINT(DBG_CONS, DBG_ERROR, (void *)"blk_rr_interval(%llu) was BIGGER than blk_gen_interval(%lu).\n",
                                blk_rr_interval, p_tier->blk_gen_interval);
                }
#else
                gen_interval = cons_cal_blk_gen_interval();
#endif
                gen_time = 0;
            }

            DBG_PRINT(DBG_CONS, DBG_INFO, (void *)"gen_interval(%d) blk_num(0x%016llX)\n", gen_interval, p_tier->blk_num);

            timer_sw_reg((uint8_t *)"stoptx", true, gen_interval, gen_time, cons_timer_tx_stop, 0);
        } while (0);

    }
    else
    {
        if (p_tier->blk_gen_sub_intrvl)
        {
            uint32_t gen_sub_intrvl = p_tier->blk_gen_sub_intrvl * 1000;
            timer_sw_reg((uint8_t *)"stoptx", true, gen_sub_intrvl, 0, cons_timer_tx_stop, 0);
        }
        else
        {
            cons_timer_tx_stop(0);
        }
    }

    return (SUCCESS_);
}

void cons_rr_init(void)
{
    cons_rr_net_init();
}

int32_t cons_rr_blk_gen_start(void)
{
    CONS_CNTX_T *p_cons_cntx = cons_get_cntx();
    CONS_TIER_T *p_tier;
    int32_t ret = ERROR_;

    DBG_PRINT (DBG_CONS, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    p_tier = &p_cons_cntx->net.tier[CONS_TIER_0];

    DBG_PRINT (DBG_CONS, DBG_INFO, (void *)"is_my_subnet_cn (%d)\n", p_tier->blk_gen_interval);

    // If the NN is the first Node to make block,
    if (p_tier->nn_gen_seq.my_root_nn_idx == 0)
    {
        cons_tx_stop();
    }

    return (ret);
}

int32_t cons_rr_blk_gen_stop(void)
{
    return (SUCCESS_);
}

int32_t cons_rr_chk_blk_gen_stop(void)
{
    P2P_CNTX_T *p_p2p_cntx = p2p_get_cntx();
    CONS_CNTX_T *p_cons_cntx = cons_get_cntx();
    CONS_TIER_T *p_tier;

    DBG_PRINT (DBG_CONS, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    p_tier = &p_cons_cntx->net.tier[CONS_TIER_0];

    if (!p_tier->nn_gen_seq.total_nn)
    {
        DBG_PRINT (DBG_CONS, DBG_ERROR, (void *)"total_nn (%d)\n", p_tier->nn_gen_seq.total_nn);
        return (SUCCESS_);
    }

    if (IS_MY_SUBNET_ADDR(p_tier->nn_gen_seq.root[CONS_1ST_NN_IDX].nn_p2p_addr, p_p2p_cntx->my_cluster_root))
    {
        uint32_t revision;
        
        revision = json_cons_rr_net_chk_ver();
        if (revision > p_cons_cntx->net.revision)
        {
            DBG_PRINT(DBG_CONS, DBG_ERROR, (void *)"RR Net Revision is different. - prv(%d) cur(%d)\n", 
                            p_cons_cntx->net.revision, revision);
        
            return (SUCCESS_);
        }
    }

    if(p_tier->blk_gen_stop != CONS_BLK_GEN_STOP_DISABLED)
    {
        DBG_PRINT(DBG_CONS, DBG_ERROR, (void *)"blk_gen_stop(%d)\n", p_tier->blk_gen_stop);
        
        return (SUCCESS_);
    }

    return (ERROR_);
}

int32_t cons_rr_set_blk_gen_stop(CONS_BLK_GEN_STOP_E blk_gen_stop)
{
    CONS_CNTX_T *p_cons_cntx = cons_get_cntx();
    CONS_TIER_T *p_tier;

    DBG_PRINT (DBG_CONS, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    if(!p_cons_cntx->net.tier_num)
    {
        return (SUCCESS_);
    }

    p_tier = &p_cons_cntx->net.tier[CONS_TIER_0];

    p_tier->blk_gen_stop = blk_gen_stop;

    return (SUCCESS_);
}

void cons_rr_geninfo_run(void)
{
    DBG_PRINT (DBG_CONS, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    
    cons_rr_init();
    
    json_cons_rr_update();
    cons_rr_net_set_next_nn();

    cons_rr_blk_gen_start();
}

