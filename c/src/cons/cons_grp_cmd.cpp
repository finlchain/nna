/**
    @file cons_grp_cmd.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

void cons_cmd_join_ind (int32_t peer_sockfd, struct sockaddr_in *p_peer_sock_addr, uint64_t peer_p2p_addr, P2P_NODE_T *p_node)
{   
    P2P_CNTX_T *p_p2p_cntx = p2p_get_cntx();

    DBG_PRINT (DBG_CONS, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    DBG_PRINT (DBG_CONS, DBG_INFO, (void *)"peer_p2p_addr(0x%016llX), node_type(0x%02X), node_rule(0x%02X)\n", 
                                peer_p2p_addr, p_node->node_type, p_node->node_rule);

    if (!(p_p2p_cntx->my_node_info.node_rule & P2P_NODE_RULE_NN))
    {
        DBG_PRINT (DBG_CONS, DBG_ERROR, (void *)"I'm not a NN.\n");
        ASSERT_M(0);
        return;
    }

    if (p_node->node_rule & P2P_NODE_RULE_NN)
    {
        // From my subnet to me.
        if (IS_MY_SUBNET_ADDR(peer_p2p_addr, p_p2p_cntx->my_cluster_root))
        {
            cons_peer_set_nn(peer_sockfd, p_peer_sock_addr, peer_p2p_addr);
        }
        // From other subnet to me.
        else
        {
            //cons_set_prv_subnet(peer_sockfd, p_peer_sock_addr, peer_p2p_addr);

            cons_send_pubkey_noti(peer_sockfd, (uint8_t *)&peer_p2p_addr);
        }
    }    
    else
    {
        DBG_PRINT(DBG_CONS, DBG_ERROR, (void *)"Peer Node Set Error\n");
    }
}

void cons_cmd_join_cfm (int32_t peer_sockfd, struct sockaddr_in *p_peer_sock_addr, uint64_t peer_p2p_addr)
{
    P2P_CNTX_T *p_p2p_cntx = p2p_get_cntx();
    
    DBG_PRINT (DBG_CONS, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    DBG_PRINT(DBG_CONS, DBG_INFO, (void *)"nn_p2p_addr (0x%016llX)\n", peer_p2p_addr);

    // From my subnet to me.
    if (IS_MY_SUBNET_ADDR(peer_p2p_addr, p_p2p_cntx->my_cluster_root))
    {
        cons_peer_set_nn(peer_sockfd, p_peer_sock_addr, peer_p2p_addr);

        cons_send_pubkey_noti(peer_sockfd, (uint8_t *)&peer_p2p_addr);
    }
    // From other subnet to me.
    else
    {
        if (!(p_p2p_cntx->my_node_info.node_rule & P2P_NODE_RULE_NN))
        {
            DBG_PRINT (DBG_CONS, DBG_ERROR, (void *)"I'm not a NN, too.\n");
            ASSERT_M(0);
            return;
        }

        cons_set_nxt_nn(peer_sockfd, p_peer_sock_addr, peer_p2p_addr);
    }
}

void cons_cmd_block_noti(int32_t sockfd, uint8_t *p_dst_p2p_addr, char *p_pubkey_path, 
                                CONS_LIGHT_BLK_T *p_light_blk, CONS_DBKEY_T *p_db_key_list)
{
    CONS_BLOCK_NOTI_T *p_block_noti;
    uint32_t len;
    
    DBG_PRINT(DBG_CONS, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    len = sizeof(CONS_BLOCK_NOTI_T);

    p_block_noti = (CONS_BLOCK_NOTI_T *)MALLOC_M(len);

    if (p_block_noti)
    {
        P2P_CNTX_T *p_p2p_cntx = p2p_get_cntx();
        CONS_CNTX_T *p_cons_cntx = cons_get_cntx();
        
        CONS_LIGHT_BLK_T *p_light_blk_s;
        CONS_DBKEY_T *p_dbkey_list_s;

        //
        if (p_p2p_cntx->my_node_info.node_rule & P2P_NODE_RULE_NN)
        {
            p_block_noti->grp_hdr.type_cmd = CONS_SRVC_CMDTYPE_SET_GRP(CONS_SRVC_CMD_BLOCK_NOTI);
        }
        p_block_noti->grp_hdr.len_sig = CONS_SRVC_LEN_SET_GRP(len - sizeof(CONS_GRP_HDR_T));
        p_block_noti->grp_hdr.len_sig |= CONS_SRVC_SIG_SET_GRP(p_cons_cntx->my_comp_pubkey[0]);

        MEMCPY_REV2(&p_block_noti->grp_hdr.type_cmd, BYTE_2);
        MEMCPY_REV2(&p_block_noti->grp_hdr.len_sig, BYTE_2);
        
        //
        p_light_blk_s = &p_block_noti->sub.light_blk;
        p_dbkey_list_s = &p_block_noti->sub.dbkey_list;
        
        MEMCPY_REV(&p_light_blk_s->blk_num, &p_light_blk->blk_num, BLK_NUM_SIZE);
        MEMCPY_REV(&p_light_blk_s->p2p_addr, &p_light_blk->p2p_addr, P2P_ADDR_LEN);
        MEMCPY_REV(&p_light_blk_s->bgt, &p_light_blk->bgt, BGT_SIZE);
        MEMCPY_REV(p_light_blk_s->pbh, p_light_blk->pbh, HASH_SIZE);
        MEMCPY_REV(&p_light_blk_s->tx_cnt, &p_light_blk->tx_cnt, BYTE_4);
        MEMCPY_REV(p_light_blk_s->blk_hash, p_light_blk->blk_hash, HASH_SIZE);
        MEMCPY_REV(p_light_blk_s->sig, p_light_blk->sig, SIG_SIZE);
        MEMCPY_REV(p_light_blk_s->sig_pubkey, p_light_blk->sig_pubkey, COMP_PUBKEY_SIZE);

        MEMCPY_REV(&p_dbkey_list_s->info.last_tx_db_key, &p_db_key_list->info.last_tx_db_key, DB_KEY_SIZE);
        MEMCPY_REV(&p_dbkey_list_s->info.first_tx_db_key, &p_db_key_list->info.first_tx_db_key, DB_KEY_SIZE);
        
        //
        DBG_PRINT(DBG_CONS, DBG_NONE, (void *)"blk_num (0x%016llX)\n", p_light_blk->blk_num);
        DBG_PRINT(DBG_CONS, DBG_NONE, (void *)"p2p_addr (0x%016llX)\n", p_light_blk->p2p_addr);
        DBG_PRINT(DBG_CONS, DBG_NONE, (void *)"blk_gen_time (0x%016llX)\n", p_light_blk->bgt);
        DBG_DUMP(DBG_CONS, DBG_NONE, (void *)"prv_blk_hash", (uint8_t *)p_light_blk->pbh, HASH_SIZE);
        DBG_PRINT(DBG_CONS, DBG_NONE, (void *)"tx_cnt (%d)\n", p_light_blk->tx_cnt);
        DBG_DUMP(DBG_CONS, DBG_NONE, (void *)"blk_hash", (uint8_t *)p_light_blk->blk_hash, HASH_SIZE);
        DBG_DUMP(DBG_CONS, DBG_NONE, (void *)"sig", (uint8_t *)p_light_blk->sig, SIG_SIZE);
        DBG_DUMP(DBG_CONS, DBG_NONE, (void *)"sig_pubkey", (uint8_t *)p_light_blk->sig_pubkey, COMP_PUBKEY_SIZE);
        
        DBG_PRINT(DBG_CONS, DBG_NONE, (void *)"last_tx_db_key (0x%016llX)\n", p_db_key_list->info.last_tx_db_key);
        DBG_PRINT(DBG_CONS, DBG_NONE, (void *)"first_tx_db_key (0x%016llX)\n", p_db_key_list->info.first_tx_db_key);

        //
        p2p_data_req(sockfd, NULL, p_pubkey_path, (uint8_t *)p_block_noti, len, p_dst_p2p_addr);

        FREE_M(p_block_noti);
    }
}

// From NN to NN'
int32_t cons_cmd_block_noti_ind(int32_t rx_sockfd, struct sockaddr_in *p_peer_sock_addr, P2P_GRP_HDR_T *p_grp_hdr, CONS_SRVC_IND_T *p_cons_ind)
{
    CONS_BLOCK_NOTI_IND_T *p_block_noti_ind = (CONS_BLOCK_NOTI_IND_T *)p_cons_ind->buf;
    CONS_LIGHT_BLK_T *p_light_blk;
    CONS_DBKEY_T *p_db_key_list;

    CONS_CNTX_T *p_cons_cntx = cons_get_cntx();
    P2P_CNTX_T *p_p2p_cntx = p2p_get_cntx();

    CONS_TIER_T *p_tier;

    DBG_PRINT(DBG_CONS, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    //
    p_light_blk = &p_block_noti_ind->sub.light_blk;
    p_db_key_list = &p_block_noti_ind->sub.dbkey_list;
    
    MEMCPY_REV2(&p_light_blk->blk_num, BLK_NUM_SIZE);
    MEMCPY_REV2(&p_light_blk->p2p_addr, P2P_ADDR_LEN);
    MEMCPY_REV2(&p_light_blk->bgt, BGT_SIZE);
    MEMCPY_REV2(p_light_blk->pbh, HASH_SIZE);
    MEMCPY_REV2(&p_light_blk->tx_cnt, BYTE_4);
    MEMCPY_REV2(p_light_blk->blk_hash, HASH_SIZE);
    MEMCPY_REV2(p_light_blk->sig, SIG_SIZE);
    MEMCPY_REV2(p_light_blk->sig_pubkey, COMP_PUBKEY_SIZE);

    MEMCPY_REV2(&p_db_key_list->info.last_tx_db_key, DB_KEY_SIZE);
    MEMCPY_REV2(&p_db_key_list->info.first_tx_db_key, DB_KEY_SIZE);
    
    DBG_PRINT(DBG_CONS, DBG_NONE, (void *)"blk_num (0x%016llX)\n", p_light_blk->blk_num);
    DBG_PRINT(DBG_CONS, DBG_NONE, (void *)"p2p_addr (0x%016llX)\n", p_light_blk->p2p_addr);
    DBG_PRINT(DBG_CONS, DBG_NONE, (void *)"blk_gen_time (0x%016llX)\n", p_light_blk->bgt);
    DBG_DUMP(DBG_CONS, DBG_NONE, (void *)"prv_blk_hash", p_light_blk->pbh, HASH_SIZE);
    DBG_PRINT(DBG_CONS, DBG_NONE, (void *)"tx_cnt (0x%08X)\n", p_light_blk->tx_cnt);
    DBG_DUMP(DBG_CONS, DBG_NONE, (void *)"blk_hash", (uint8_t *)p_light_blk->blk_hash, HASH_SIZE);
    DBG_DUMP(DBG_CONS, DBG_NONE, (void *)"sig", (uint8_t *)p_light_blk->sig, SIG_SIZE);
    DBG_DUMP(DBG_CONS, DBG_NONE, (void *)"sig_pubkey", (uint8_t *)p_light_blk->sig_pubkey, COMP_PUBKEY_SIZE);

    DBG_PRINT(DBG_CONS, DBG_NONE, (void *)"last_tx_db_key (0x%016llX)\n", p_db_key_list->info.last_tx_db_key);
    DBG_PRINT(DBG_CONS, DBG_NONE, (void *)"first_tx_db_key (0x%016llX)\n", p_db_key_list->info.first_tx_db_key);

    // Check Signature Verification
    if (p_light_blk->sig_pubkey[0] == CONS_GRP_HDR_SIG_ECDSA)
    {
        openssl_ecdsa_verify(p_light_blk->blk_hash, HASH_SIZE, (SSL_SIG_U *)p_light_blk->sig, &p_light_blk->sig_pubkey[0]);
    }
    else if (p_light_blk->sig_pubkey[0] == CONS_GRP_HDR_SIG_ED25519)
    {
        openssl_ed25519_verify(p_light_blk->blk_hash, HASH_SIZE, (SSL_SIG_U *)p_light_blk->sig, &p_light_blk->sig_pubkey[1]);
    }
    else
    {
        ASSERT_M(0);
    }

    //
    p_tier = &p_cons_cntx->net.tier[CONS_TIER_0];

    // 
    if (!IS_MY_SUBNET_ADDR(p_block_noti_ind->sub.light_blk.p2p_addr, p_p2p_cntx->my_cluster_root))
    {
        DBG_PRINT(DBG_CONS, DBG_WARN, (void *)"2 p2p_addr(0x%016llX), blk_num(0x%016llX), tx_cnt(%d)\n", 
                                p_light_blk->p2p_addr, p_light_blk->blk_num, p_light_blk->tx_cnt);

        // NN
        if ((p_p2p_cntx->my_node_info.node_rule & P2P_NODE_RULE_NN))
        {
            // From Previous NN
            if (!IS_MY_SUBNET_ADDR(p_block_noti_ind->sub.light_blk.p2p_addr, p_tier->nn_gen_seq.root[p_tier->nn_gen_seq.my_prev_nn_idx].nn_p2p_addr))
            {
                DBG_PRINT(DBG_CONS, DBG_ERROR, (void *)"PRV BLK ERR : my_prev_nn_idx(%d) prv_nn_addr(0x%016llX) prv_blk_p2p_addr(0x%016llX)\n", 
                                        p_tier->nn_gen_seq.my_prev_nn_idx, 
                                        p_tier->nn_gen_seq.root[p_tier->nn_gen_seq.my_prev_nn_idx].nn_p2p_addr, p_block_noti_ind->sub.light_blk.p2p_addr);

                return (ERROR_);
            }
        }
        
        if(p_block_noti_ind->sub.light_blk.p2p_addr != p_p2p_cntx->my_p2p_addr.u64)
        {
            //
        }

        cons_update_prv_blk_info(p_light_blk);
    }    

    if (p_p2p_cntx->my_node_info.node_rule & P2P_NODE_RULE_NN)
    {
        DBG_PRINT(DBG_CONS, DBG_INFO, (void *)"From other NN.\n");
        cons_tx_stop();
    }    

    return (SUCCESS_);
}

static int32_t cons_cmd_pubkey_noti_ind_process(int32_t sockfd, uint64_t peer_p2p_addr, uint8_t *p_pubkey)
{
    CONS_CNTX_T *p_cons_cntx = cons_get_cntx();
    P2P_CNTX_T *p_p2p_cntx = p2p_get_cntx();

    int32_t ret = ERROR_;

    // Compressed Public Key to PEM file
    // Store the PEM file at key/p2p_addr
    // 1. generate directory, save path(key/p2p_addr)
    // 2. function call openssl_hex2pem with(path, comp_pubkey)

    // From other subnet
    if (!IS_MY_SUBNET_ADDR(peer_p2p_addr, p_p2p_cntx->my_cluster_root))
    {
        if (p_p2p_cntx->my_node_info.node_rule & P2P_NODE_RULE_NN)
        {
            CONS_GEN_INFO_T *p_nn_gen_info;
            
            p_nn_gen_info = cons_get_nxt_nn(peer_p2p_addr);
            if (p_nn_gen_info)
            {
                int32_t my_ret;
                
                ASSERT_M(p_nn_gen_info->actived == true);

                cons_set_pubkey_dir(peer_p2p_addr, p_nn_gen_info->nn_pubkey_dir);
                my_ret = cons_pubkey_mkdir(p_nn_gen_info->nn_pubkey_dir);
                
                if (my_ret > 0)
                {
                    cons_set_pubkey_path(p_nn_gen_info->nn_pubkey_dir, p_cons_cntx->pubkey_name, p_nn_gen_info->nn_pubkey_path);
                    cons_pubkey_add(p_nn_gen_info->nn_pubkey_path, p_pubkey);
                }
                else
                {
                    ASSERT_M(0);
                }

                ret = SUCCESS_;
            }
        }
    }
    
    return (ret);
}

#if (P2P_PUBKEY_NOTI == DISABLED)
void cons_cmd_pubkey_noti(int32_t sockfd, uint8_t *p_dst_p2p_addr, char *p_pubkey_path, uint8_t *p_comp_pubkey)
{
    CONS_PUBKEY_NOTI_T cons_pubkey_noti;
    uint32_t len = sizeof(CONS_PUBKEY_NOTI_T);
    uint16_t len_sig;
    CONS_CNTX_T *p_cons_cntx = cons_get_cntx();
    
    DBG_PRINT(DBG_CONS, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    
    //
    cons_pubkey_noti.grp_hdr.type_cmd = CONS_SRVC_CMDTYPE_SET_GRP(CONS_SRVC_CMD_PUBKEY_NOTI);
    cons_pubkey_noti.grp_hdr.len_sig = CONS_SRVC_LEN_SET_GRP(len - sizeof(CONS_GRP_HDR_T));
    cons_pubkey_noti.grp_hdr.len_sig |= CONS_SRVC_SIG_SET_GRP(p_cons_cntx->my_comp_pubkey[0]);
    len_sig = cons_pubkey_noti.grp_hdr.len_sig;
    MEMCPY_REV2(&cons_pubkey_noti.grp_hdr.type_cmd, BYTE_2);
    MEMCPY_REV2(&cons_pubkey_noti.grp_hdr.len_sig, BYTE_2);
    
    //
    switch (CONS_SRVC_SIG_GET_GRP(len_sig))
    {
    case CONS_GRP_HDR_SIG_ECDSA:
        MEMCPY_REV(cons_pubkey_noti.sub.pubkey, p_comp_pubkey, COMP_PUBKEY_SIZE);
        break;

    case CONS_GRP_HDR_SIG_ED25519:
        MEMCPY_REV(cons_pubkey_noti.sub.pubkey, p_comp_pubkey, (1+ED25519_PUBLIC_KEY_LEN_));
        break;

    default :
        break;
    }

    //
    p2p_data_req(sockfd, NULL, p_pubkey_path, (uint8_t *)&cons_pubkey_noti, len, p_dst_p2p_addr);
}

int32_t cons_cmd_pubkey_noti_ind (int32_t rx_sockfd, struct sockaddr_in *p_peer_sock_addr, P2P_GRP_HDR_T *p_grp_hdr,  CONS_SRVC_IND_T *p_cons_ind)
{
    CONS_PUBKEY_NOTI_IND_T *p_pubkey_ind = (CONS_PUBKEY_NOTI_IND_T *)p_cons_ind->buf;
    int32_t sig_type;
    int32_t ret;

    DBG_PRINT(DBG_CONS, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    sig_type = CONS_SRVC_SIG_GET_GRP(p_cons_ind->grp_hdr.len_sig);
    switch (sig_type)
    {
    case CONS_GRP_HDR_SIG_ECDSA:
        MEMCPY_REV2(p_pubkey_ind->sub.pubkey, COMP_PUBKEY_SIZE);
        break;

    case CONS_GRP_HDR_SIG_ED25519:
        MEMCPY_REV2(p_pubkey_ind->sub.pubkey, (1+ED25519_PUBLIC_KEY_LEN_));
        break;

    default :
        ASSERT_M(0);
        break;
    }

    ret = cons_cmd_pubkey_noti_ind_process(rx_sockfd, p_grp_hdr->src_addr, p_pubkey_ind->sub.pubkey);

    return (ret);
}
#else
int32_t cons_cmd_pubkey_noti_ind (int32_t peer_sockfd, struct sockaddr_in *p_peer_sock_addr, uint64_t peer_p2p_addr, uint8_t *p_pubkey)
{
    int32_t ret;
    
    ret = cons_cmd_pubkey_noti_ind_process(peer_sockfd, peer_p2p_addr, p_pubkey);

    return (ret);
}
#endif // P2P_PUBKEY_NOTI

