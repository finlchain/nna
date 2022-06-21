/**
    @file cons.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

CONS_CNTX_T g_cons_cntx;

bool cons_test_get_tx_rollback(void)
{
    return (g_cons_cntx.cons_test.tx_rollback);
}

void cons_test_set_tx_rollback(bool tx_rollback)
{
    g_cons_cntx.cons_test.tx_rollback = tx_rollback;
}

void cons_update_prv_blk_info(CONS_LIGHT_BLK_T *p_prv_blk)
{
    CONS_CNTX_T *p_cons_cntx = cons_get_cntx();
    CONS_TIER_T *p_tier;

    p_tier = &p_cons_cntx->net.tier[CONS_TIER_0];

    p_tier->prv_blk_num = p_prv_blk->blk_num;
    p_tier->prv_blk_gen_addr = p_prv_blk->p2p_addr;
    MEMCPY_M(p_tier->prv_blk_hash, p_prv_blk->blk_hash, HASH_SIZE);

    {
        uint64_t cur_utc_ms;
        
        cur_utc_ms = util_curtime_ms();
        if (cur_utc_ms <= p_tier->prv_bgt)
        {
            DBG_PRINT(DBG_CONS, DBG_ERROR, (void *)"cur_utc_ms(%llu) prv_bgt(%llu)\n", cur_utc_ms, p_tier->prv_bgt);    
        }
        
        p_tier->prv_bgt = p_prv_blk->bgt;
    }
}

uint32_t cons_cal_blk_gen_interval(void)
{
    CONS_CNTX_T *p_cons_cntx = cons_get_cntx();
    CONS_TIER_T *p_tier;
    uint64_t cur_utc_ms, interval;

    p_tier = &p_cons_cntx->net.tier[CONS_TIER_0];

    if (!p_tier->blk_gen_interval || !p_tier->prv_bgt)
    {
        return (p_tier->blk_gen_interval);
    }

    cur_utc_ms = util_curtime_ms();

    if (cur_utc_ms <= p_tier->prv_bgt)
    {
        interval = 0;
        DBG_PRINT(DBG_CONS, DBG_ERROR, (void *)"cur_utc_ms(%llu) prv_bgt(%llu)\n", cur_utc_ms, p_tier->prv_bgt);    
    }
    else
    {
        interval = cur_utc_ms - p_tier->prv_bgt;
        DBG_PRINT(DBG_CONS, DBG_NONE, (void *)"cur_utc_ms(%llu) prv_bgt(%llu) interval(%llu)\n", cur_utc_ms, p_tier->prv_bgt, interval);
    }

    if (interval >= p_tier->blk_gen_interval)
    {
        return (0);
    }
    
    return (p_tier->blk_gen_interval - interval);
}

void cons_set_prikey_enc(void)
{
    CONS_CNTX_T *p_cons_cntx = cons_get_cntx();
    uint32_t start, end;
    char *p_buf;

    DBG_PRINT(DBG_CONS, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    
    end = STRLEN_M(p_cons_cntx->prikey_name);
    start = end - 3;

    p_cons_cntx->b_enc_prikey = false;

    p_buf = util_slice_str(p_cons_cntx->prikey_name, start, end);
    if (p_buf)
    {
        util_str_lower_case(p_buf, STRLEN_M(p_buf));

        if(STRCMP_M(p_buf, "pem") != 0)
        {
            p_cons_cntx->b_enc_prikey = true;
        }
        
        FREE_M(p_buf);
    }

    DBG_PRINT(DBG_CONS, DBG_INFO, (void *)"b_enc_prikey (%d)\n", p_cons_cntx->b_enc_prikey);
}

int32_t cons_set_pubkey_dir(uint64_t peer_p2p_addr, char *p_pubkey_dir)
{
    CONS_CNTX_T *p_cons_cntx = cons_get_cntx();
    uint32_t cluster_addr = peer_p2p_addr & P2P_CLUSTER_ADDR_MASK;

    DBG_PRINT(DBG_CONS, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    
    sprintf(p_pubkey_dir, "%s%08X", p_cons_cntx->key_dir, cluster_addr);
    DBG_PRINT(DBG_CONS, DBG_INFO, (void *)"peer_pubkey_dir (%s)\n", p_pubkey_dir);

    return(SUCCESS_);
}

int32_t cons_pubkey_mkdir(char *p_pubkey_dir)
{
    int32_t ret;

    DBG_PRINT(DBG_CONS, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    ret = util_create_dir(p_pubkey_dir);
    
    return (ret);
}

int32_t cons_pubkey_rmdir(char *p_pubkey_dir)
{
    int32_t ret;

    ret = util_remove_dir(p_pubkey_dir);

    return (ret);
}

int32_t cons_set_pubkey_path(char *p_pubkey_dir, char *p_name, char *p_pubkey_path)
{
    sprintf(p_pubkey_path, "%s/%s", p_pubkey_dir, p_name);
    
    DBG_PRINT(DBG_CONS, DBG_INFO, (void *)"pubkey_path (%s)\n", p_pubkey_path);

    return (SUCCESS_);
}

int32_t cons_pubkey_add(char *p_pubkey_path, uint8_t *p_pubkey)
{
    int32_t ret;
    
    ret = PEM_write_raw_PUBKEY(p_pubkey_path, p_pubkey);

    return (ret);
}

int32_t cons_pubkey_del(char *p_pubkey_path)
{
    int32_t ret;
    
    DBG_PRINT(DBG_CONS, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    
    ret = util_remove_file(p_pubkey_path); // rm pubkey.pem
    
    return (ret);
}

CONS_PEER_T *cons_peer_set_nn(uint32_t peer_sock_fd, struct sockaddr_in *p_peer_sock_addr, uint64_t peer_p2p_addr)
{
    CONS_CNTX_T *p_cons_cntx = cons_get_cntx();
    
    DBG_PRINT(DBG_CONS, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    if (p_cons_cntx->peer[CONS_PEER_NN_IDX].actived)
    {
        ASSERT_M(peer_p2p_addr == p_cons_cntx->peer[CONS_PEER_NN_IDX].p2p_addr);
    }
    
    p_cons_cntx->peer[CONS_PEER_NN_IDX].sockfd = peer_sock_fd;

    if (p_peer_sock_addr)
    {
        p_cons_cntx->peer[CONS_PEER_NN_IDX].sock_addr = *p_peer_sock_addr;
    }
    else
    {
        //
    }
    MEMCPY_M((uint8_t *)&p_cons_cntx->peer[CONS_PEER_NN_IDX].p2p_addr, (uint8_t *)&peer_p2p_addr, P2P_ADDR_LEN);
    p_cons_cntx->peer[CONS_PEER_NN_IDX].actived = true;
    
    return (&p_cons_cntx->peer[CONS_PEER_NN_IDX]);
}

int32_t cons_peer_del_nn(int32_t sockfd)
{
    CONS_CNTX_T *p_cons_cntx = cons_get_cntx();

    DBG_PRINT(DBG_CONS, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    
    if(p_cons_cntx->peer[CONS_PEER_NN_IDX].actived)
    {
        if (sockfd == p_cons_cntx->peer[CONS_PEER_NN_IDX].sockfd)
        {
            cons_pubkey_del(p_cons_cntx->peer[CONS_PEER_NN_IDX].pubkey_path);
            cons_pubkey_rmdir(p_cons_cntx->peer[CONS_PEER_NN_IDX].pubkey_dir);
            
            MEMSET_M(&p_cons_cntx->peer[CONS_PEER_NN_IDX], 0x00, sizeof(CONS_PEER_T));

            return (SUCCESS_);
        }
    }

    return (ERROR_);
}

int32_t cons_peer_del_all(void)
{
    CONS_CNTX_T *p_cons_cntx = cons_get_cntx();
    uint32_t idx;

    DBG_PRINT(DBG_CONS, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    for (idx=CONS_PEER_NN_IDX; idx<CONS_PEER_MAX; idx++)
    {
        if (p_cons_cntx->peer[idx].actived)
        {
            cons_pubkey_del(p_cons_cntx->peer[idx].pubkey_path);
            cons_pubkey_rmdir(p_cons_cntx->peer[idx].pubkey_dir);

            MEMSET_M(&p_cons_cntx->peer[idx], 0x00, sizeof(CONS_PEER_T));
        }
    }

    ASSERT_M (p_cons_cntx->peer_cn_num == 0);

    return (SUCCESS_);
}

CONS_GEN_INFO_T *cons_get_nxt_nn(uint64_t peer_p2p_addr)
{
    CONS_CNTX_T *p_cons_cntx = cons_get_cntx();
    CONS_GEN_SEQ_INFO_T *p_nn_gen_seq;
    CONS_GEN_INFO_T *p_nn_gen_info;
    uint32_t next_nn_idx;

    DBG_PRINT(DBG_CONS, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    p_nn_gen_seq = &p_cons_cntx->net.tier[CONS_TIER_0].nn_gen_seq;
    
    next_nn_idx = p_nn_gen_seq->my_next_nn_idx;
    p_nn_gen_info = &p_nn_gen_seq->root[next_nn_idx];
    
    if (IS_MY_SUBNET_ADDR(p_nn_gen_info->nn_p2p_addr, peer_p2p_addr))
    {
        return (p_nn_gen_info);
    }

    return (NULL);
}

int32_t cons_set_nxt_nn(int32_t peer_sock_fd, struct sockaddr_in *p_peer_sock_addr, uint64_t peer_p2p_addr)
{
    CONS_CNTX_T *p_cons_cntx = cons_get_cntx();
    CONS_GEN_SEQ_INFO_T *p_nn_gen_seq;
    CONS_GEN_INFO_T *p_nn_gen_info;
    uint32_t next_nn_idx;

    DBG_PRINT(DBG_CONS, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    DBG_PRINT(DBG_CONS, DBG_INFO, (void *)"peer_p2p_addr(0x%016llX) peer_sock_fd(%d)\n", peer_p2p_addr, peer_sock_fd);

    ASSERT_M ((peer_p2p_addr & P2P_SUB_ADDR_MASK) == P2P_SUB_ROOT_ADDR);

    p_nn_gen_seq = &p_cons_cntx->net.tier[CONS_TIER_0].nn_gen_seq;
    
    next_nn_idx = p_nn_gen_seq->my_next_nn_idx;
    p_nn_gen_info = &p_nn_gen_seq->root[next_nn_idx];
    
    if (IS_MY_SUBNET_ADDR(p_nn_gen_info->nn_p2p_addr, peer_p2p_addr))
    {
        p_nn_gen_info->actived = true;
        p_nn_gen_info->subnet.sockfd = peer_sock_fd;

        DBG_PRINT(DBG_CONS, DBG_WARN, (void *)"nxt_idx (%d) actived(%d) sockfd(%d)\n", next_nn_idx,
                    p_nn_gen_info->actived,
                    p_nn_gen_info->subnet.sockfd);
        
        return (SUCCESS_);
    }

    return (ERROR_);
}

int32_t cons_clr_nxt_nn(int32_t peer_sock_fd, struct sockaddr_in *p_peer_sock_addr, uint64_t peer_p2p_addr)
{
    CONS_CNTX_T *p_cons_cntx = cons_get_cntx();
    CONS_GEN_SEQ_INFO_T *p_nn_gen_seq;
    CONS_GEN_INFO_T *p_nn_gen_info;
    uint32_t next_nn_idx;

    DBG_PRINT(DBG_CONS, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    DBG_PRINT(DBG_CONS, DBG_INFO, (void *)"peer_p2p_addr(0x%016llX) peer_sock_fd(%d)\n", peer_p2p_addr, peer_sock_fd);

    ASSERT_M ((peer_p2p_addr & P2P_SUB_ADDR_MASK) == P2P_SUB_ROOT_ADDR);

    p_nn_gen_seq = &p_cons_cntx->net.tier[CONS_TIER_0].nn_gen_seq;
    
    next_nn_idx = p_nn_gen_seq->my_next_nn_idx;
    p_nn_gen_info = &p_nn_gen_seq->root[next_nn_idx];
    
    if ((peer_sock_fd > 0) && (peer_sock_fd == p_nn_gen_info->subnet.sockfd))
    {
        p_nn_gen_info->actived = false;
        p_nn_gen_info->subnet.sockfd = -1;

        cons_pubkey_del(p_nn_gen_info->nn_pubkey_path);
        cons_pubkey_rmdir(p_nn_gen_info->nn_pubkey_dir);
        
        MEMSET_M(p_nn_gen_info->nn_pubkey_dir, 0x00, CONS_DIR_SIZE);
        MEMSET_M(p_nn_gen_info->nn_pubkey_path, 0x00, CONS_PATH_SIZE);

        DBG_PRINT(DBG_CONS, DBG_WARN, (void *)"nxt_idx (%d) actived(%d) sockfd(%d)\n", next_nn_idx,
                    p_nn_gen_info->actived,
                    p_nn_gen_info->subnet.sockfd);

        p_nn_gen_seq->my_next_nn_idx = NXT_IDX(p_nn_gen_seq->my_next_nn_idx, p_nn_gen_seq->total_nn);

        //if (p_nn_gen_seq->my_root_nn_idx != p_nn_gen_seq->my_next_nn_idx)
        //{
        cons_rr_net_set_next_nn();
        //}
        
        return (SUCCESS_);
    }

    return (ERROR_);
}

int32_t cons_send_block_noti(uint32_t to_nn, CONS_LIGHT_BLK_T *p_light_blk, CONS_DBKEY_T *p_db_key_list)
{
    CONS_CNTX_T *p_cons_cntx = cons_get_cntx();
    CONS_TIER_T *p_tier;

    uint32_t next_nn_idx;

    DBG_PRINT(DBG_CONS, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    p_tier = &p_cons_cntx->net.tier[CONS_TIER_0];

    // important **  point at which nn's block number increases
    p_tier->blk_num += p_tier->nn_gen_seq.total_nn;

    //
    if (cons_rr_chk_blk_gen_stop() == SUCCESS_)
    {
        return (ERROR_);
    }

    next_nn_idx = p_tier->nn_gen_seq.my_next_nn_idx;

    if (to_nn)
    {
        // to SCA
#if defined (USE_DB_REDIS)
#if (REDIS_SUB_TX_NEW == ENABLED)
        task_send_msg(&db_redis_task_pool, &db_redis_task_list, (uint8_t *)p_light_blk, sizeof(CONS_LIGHT_BLK_T), false, DB_REDIS_TASK_MSG_EVENT_03);
#else
        redis_pub_blk_noti(p_light_blk);
#endif // REDIS_SUB_TX_NEW
#endif // USE_DB_REDIS

        if((p_tier->nn_gen_seq.my_root_nn_idx != next_nn_idx) && (p_tier->nn_gen_seq.root[next_nn_idx].subnet.sockfd > 0))
        {
            DBG_PRINT(DBG_CONS, DBG_INFO, (void *)"From NN to NN'.\n");

            cons_cmd_block_noti(  p_tier->nn_gen_seq.root[next_nn_idx].subnet.sockfd, 
                                  (uint8_t *)&p_tier->nn_gen_seq.root[next_nn_idx].nn_p2p_addr, 
                                  NULL, 
                                  p_light_blk, p_db_key_list);
        }
        else
        {
            DBG_PRINT(DBG_CONS, DBG_INFO, (void *)"NN is only ONE.\n");

            cons_tx_stop();
        }
    }
    else
    {
        ASSERT_M(0);
    }
    
    return (ERROR_);
}

#if (REDIS_SUB_TX == ENABLED)
// From SCA to NN DB
int32_t cons_send_tx(uint32_t tx_cnt, CONS_TX_INFO_T *p_tx_info)
{
    int32_t ret = ERROR_;

    CONS_CNTX_T *p_cons_cntx = cons_get_cntx();
    CONS_TIER_T *p_tier;

    DBG_PRINT(DBG_CONS, DBG_NONE, (void *)"(%s)\n", __FUNCTION__);
    
    p_tier = &p_cons_cntx->net.tier[CONS_TIER_0];    
    
    do
    {
        uint32_t idx;

        DBG_PRINT(DBG_CONS, DBG_NONE, (void *)"(%s)\n", __FUNCTION__);
#if (CONS_TO_DB_TASK == ENABLED)
        DB_TX_FIELD_T *p_tx_field;
        uint32_t tx_len;
    
        tx_len = sizeof(DB_TX_FIELD_T)*tx_cnt;
        p_tx_field = (DB_TX_FIELD_T *)MALLOC_M(tx_len);
    
    
        for (idx=0; idx<tx_cnt; idx++)
        {
            p_tx_field[idx].blk_num = p_tier->blk_num;
            p_tx_field[idx].db_key = p_tx_info[idx].db_key;
            MEMCPY_M(p_tx_field[idx].sc_hash, p_tx_info[idx].sc_hash, HASH_SIZE);
        }
    
        ret = task_send_msg(&db_task_pool, &db_task_list, (uint8_t *)p_tx_field, tx_len, false, DB_TASK_MSG_EVENT_01);
    
        FREE_M(p_tx_field);
#else
        for (idx=0; idx<tx_cnt; idx++)
        {
            ret = DB_INSERT_T_BLK_TX(p_tier->blk_num, p_tx_info[idx].db_key, p_tx_info[idx].sc_hash);
            if (ret != DB_RESULT_SUCCESS)
            {
                break;
            }
        }
#endif // CONS_TO_DB_TASK
        if (ret != SUCCESS_)
        {
            ASSERT_M(0);
        }
    
    }while(0);

    //cons_send_tx_ack(ret, p_tier->blk_num, tx_cnt, p_tx_info);
    
    return (ret);
}

// NN to SCA
int32_t cons_send_tx_ack (uint32_t result, uint64_t blk_num, uint32_t tx_cnt, CONS_TX_INFO_T *p_tx_info)
{
    P2P_CNTX_T *p_p2p_cntx = p2p_get_cntx();
    CONS_TX_ACK_INFO_T *p_tx_ack;
    uint32_t len, idx;
    int32_t ret = ERROR_;

    DBG_PRINT(DBG_CONS, DBG_NONE, (void *)"(%s)\n", __FUNCTION__);

    len = sizeof(CONS_TX_ACK_INFO_T) + (tx_cnt * DB_KEY_SIZE);
    p_tx_ack = (CONS_TX_ACK_INFO_T *)MALLOC_M(len);
    
    p_tx_ack->result = CONS_RESULT_FAILURE;
    if (result == SUCCESS_)
    {
        p_tx_ack->result = CONS_RESULT_SUCCESS;
    }

    p_tx_ack->blk_num = blk_num;
    p_tx_ack->cnt = tx_cnt;

    for (idx=0; idx<tx_cnt; idx++)
    {
        p_tx_ack->db_key[idx] = p_tx_info[idx].db_key;
    }
    
    //
#if defined (USE_DB_REDIS)
#if (REDIS_SUB_TX_NEW == ENABLED)
    ret = task_send_msg(&db_redis_task_pool, &db_redis_task_list, (uint8_t *)p_tx_ack, len, false, DB_REDIS_TASK_MSG_EVENT_02);
#else
    ret = redis_pub_tx_ack(p_tx_ack);
#endif // REDIS_SUB_TX_NEW
#endif // USE_DB_REDIS
    
    if (p_p2p_cntx->my_node_info.node_rule & P2P_NODE_RULE_NN)
    {
        DBG_PRINT(DBG_CONS, DBG_NONE, (void *)"(%s) - NN\n", __FUNCTION__);

        if (cons_test_get_tx_rollback() == true)
        {
            if (p_tx_ack->result == CONS_RESULT_SUCCESS)
            {
                cons_fsdump_temp(0);
            }
            else
            {
                DBG_PRINT(DBG_CONS, DBG_ERROR, (void *)"(%s) Error\n", __FUNCTION__);
                for (idx=0; idx<tx_cnt; idx++)
                {
                    DBG_PRINT(DBG_CONS, DBG_ERROR, (void *)"p_cons->db_key (0x%016llX)\n", p_tx_info[idx].db_key);
                }

            }
        }
    }
    else
    {
        ASSERT_M(0);
    }

    FREE_M(p_tx_ack);

    return (ret);
}
#endif // REDIS_SUB_TX

int32_t cons_set_my_pubkey(void)
{
    int32_t ret = ERROR_;
    CONS_CNTX_T *p_cons_cntx = cons_get_cntx();

    DBG_PRINT(DBG_CONS, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    ret = openssl_ec_pubkey_pem2hex(p_cons_cntx->my_pubkey_path, &p_cons_cntx->my_comp_pubkey[0]);
    if(ret != SUCCESS_)
    {
        p_cons_cntx->my_comp_pubkey[0] = PUBKEY_DELIMITER_25519;
        ret = openssl_ed_pubkey_pem2hex(p_cons_cntx->my_pubkey_path, &p_cons_cntx->my_comp_pubkey[1]);
        ASSERT_M(ret == SUCCESS_);
    }

    DBG_DUMP(DBG_CONS, DBG_INFO, (void *)"1 my_pubkey : ", p_cons_cntx->my_comp_pubkey, COMP_PUBKEY_SIZE);

    return (ret);
}

int32_t cons_get_my_pubkey(uint8_t *p_pubkey)
{
    int32_t ret = ERROR_;
    CONS_CNTX_T *p_cons_cntx = cons_get_cntx();

    DBG_PRINT(DBG_CONS, DBG_NONE, (void *)"(%s)\n", __FUNCTION__);

    if (p_pubkey)
    {
        if ((p_cons_cntx->my_comp_pubkey[0] == CONS_GRP_HDR_SIG_ECDSA) || (p_cons_cntx->my_comp_pubkey[0] == CONS_GRP_HDR_SIG_ED25519))
        {
            ret = COMP_PUBKEY_SIZE;
            MEMCPY_M(p_pubkey, p_cons_cntx->my_comp_pubkey, COMP_PUBKEY_SIZE);
        }
    }
    
    return (ret);
}

int32_t cons_send_pubkey_noti(int32_t sockfd, uint8_t *p_dst_p2p_addr)
{
    int32_t ret = ERROR_;
    CONS_CNTX_T *p_cons_cntx = cons_get_cntx();
    uint8_t comp_pubkey[COMP_PUBKEY_SIZE];
    
    DBG_PRINT(DBG_CONS, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    // Get My Compressed Public Key (HEX)
    DBG_PRINT(DBG_CONS, DBG_NONE, (void *)"my_pubkey_path (%s)\n", p_cons_cntx->my_pubkey_path);

    ret = cons_get_my_pubkey(comp_pubkey);
    ASSERT_M(ret == COMP_PUBKEY_SIZE);

    DBG_DUMP(DBG_CONS, DBG_INFO, (void *)"2 my_pubkey : ", comp_pubkey, COMP_PUBKEY_SIZE);

#if (P2P_PUBKEY_NOTI == ENABLED)
    P2P_GRP_HDR_T grp_hdr;

    MEMCPY_M(&grp_hdr.dst_addr, p_dst_p2p_addr, P2P_ADDR_LEN);
    p2p_cmd_pubkey_noti(sockfd, NULL, &grp_hdr, comp_pubkey);
#else
    cons_cmd_pubkey_noti(sockfd, p_dst_p2p_addr, NULL, comp_pubkey);
#endif // P2P_PUBKEY_NOTI

    return (SUCCESS_);
}

static void cons_cntx_init(bool b_init)
{
    uint32_t cnt;

    if (b_init)
    {
        MEMSET_M(&g_cons_cntx, 0x00, sizeof(CONS_CNTX_T));
    }
    
    for (cnt=0; cnt<CONS_TIER_MAX; cnt++)
    {
        g_cons_cntx.net.tier[cnt].blk_num = BLK_NUM_INIT_VAL;
        g_cons_cntx.net.tier[cnt].prv_blk_num = BLK_NUM_INIT_VAL;

        g_cons_cntx.net.tier[cnt].prv_bgt = 0;
        g_cons_cntx.net.tier[cnt].prv_blk_gen_addr = P2P_NULL_ADDR;
    }
    
    json_cons_udpate();

    cons_test_set_tx_rollback(false);
}

void cons_init(bool b_init)
{
    if (b_init)
    {
        //
    }
    
    cons_cntx_init(b_init);
}

CONS_CNTX_T *cons_get_cntx(void)
{
    return (&g_cons_cntx);
}

void *t_cons_main(void *p_data)
{
    pid_t pid; // process id
    
    char* thread_name = (char*)p_data;
    bool exe_thread = true;
    int task_ret = TASK_EXIT_NORMAL;

#if (defined (_WIN32) || defined (_WIN64))
    pthread_t tid; // thread id
    
    pid = GetCurrentProcessId();
    tid = pthread_self();
#else
    pid_t tid;

    pid = getpid();
    tid = syscall(SYS_gettid);

    setpriority(PRIO_PROCESS, tid, g_tid_nice[CONS_THREAD_IDX]);
#endif

    DBG_PRINT(DBG_CLI, DBG_TRACE, (void *)"%s\n", __FUNCTION__);
    DBG_PRINT(DBG_TX, DBG_INFO, (void *)"%s is started.! - pid(%d), tid(%d)\n", thread_name, pid, tid);

    cons_timer_run();
    
    while (exe_thread)
    {
        cons_task_msg_handler();

        usleep(10);
    }

    pthread_exit(&task_ret);
    
    return (void *)p_data;
}

void cons_task_init(void)
{
    cons_init(true);
    cons_task_msg_init();
}

