/**
    @file json_parse.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

static char *json_path_path(void)
{
    char *p_cfg_path = (char *)PATH_CFG_PATH;

    DBG_PRINT (DBG_APP, DBG_INFO, (void *)"PATH_CFG_PATH : %s\n", p_cfg_path);

    return (p_cfg_path);
}

#if defined(USE_JSONC)
int32_t jsonc_path_update(void)
{
    uint32_t json_len;
    char *p_json;

    //
    json_object *p_root_obj, *p_path_obj;
    //
    json_object *p_key_obj;
    json_object *p_cons_obj;
#if 0
    //
    json_object *p_pw_obj;
    json_object *p_db_obj;
#endif
    //
    json_object *p_data;
    
	CONS_CNTX_T *p_cons_cntx = cons_get_cntx();
#if 0
    DB_PW_INFO_T *p_db_pw_info = db_get_pw_info();
#endif
    DBG_PRINT (DBG_JSON, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    p_json = util_file_r(json_path_path(), &json_len);

    p_root_obj = json_tokener_parse(p_json);
    
    p_path_obj = json_object_object_get(p_root_obj, "PATH");
//
    // KEY
    p_key_obj = json_object_object_get(p_path_obj, "KEY");

    // CONS
    p_cons_obj = json_object_object_get(p_key_obj, "CONS");
    //
    p_data = json_object_object_get(p_cons_obj, "PRIKEY_NAME");
    STRCPY_M(p_cons_cntx->prikey_name, json_object_get_string(p_data));
    //
    p_data = json_object_object_get(p_cons_obj, "PUBKEY_NAME");
    STRCPY_M(p_cons_cntx->pubkey_name, json_object_get_string(p_data));
    //
    p_data = json_object_object_get(p_cons_obj, "MY_KEY");
    STRCPY_M(p_cons_cntx->my_key_dir, json_object_get_string(p_data));
    //
    p_data = json_object_object_get(p_cons_obj, "REMOTE_KEY");
    STRCPY_M(p_cons_cntx->key_dir, json_object_get_string(p_data));

#if 0
//
    // PW
    p_key_obj = json_object_object_get(p_path_obj, "PW");

    // DB
    p_cons_obj = json_object_object_get(p_key_obj, "DB");
    //
    p_data = json_object_object_get(p_cons_obj, "PW_MARIA");
    STRCPY_M(p_db_pw_info->, json_object_get_string(p_data));
    //
    p_data = json_object_object_get(p_cons_obj, "PW_REDIS");
    STRCPY_M(sql_type_str, json_object_get_string(p_data));
    //
    p_data = json_object_object_get(p_cons_obj, "PW");
    STRCPY_M(sql_type_str, json_object_get_string(p_data));
    //
    p_data = json_object_object_get(p_cons_obj, "MY_PW");
    STRCPY_M(sql_type_str, json_object_get_string(p_data));
    //
    p_data = json_object_object_get(p_cons_obj, "REMOTE_PW");
    STRCPY_M(sql_type_str, json_object_get_string(p_data));
#endif

//
    json_object_put(p_root_obj);
    
    FREE_M(p_json);

    return (SUCCESS_);
}
#endif // USE_JSONC

int32_t json_path_update(void)
{
    int32_t ret = ERROR_;

#if defined(USE_JSONC)
    ret = jsonc_path_update();
#endif // USE_JSONC

    if (ret == SUCCESS_)
    {
        CONS_CNTX_T *p_cons_cntx = cons_get_cntx();

        sprintf(p_cons_cntx->my_prikey_path, "%s%s", p_cons_cntx->my_key_dir, p_cons_cntx->prikey_name);
        DBG_PRINT (DBG_JSON, DBG_INFO, (void *)"my_prikey_path (%s)\n", p_cons_cntx->my_prikey_path);

        sprintf(p_cons_cntx->my_pubkey_path, "%s%s", p_cons_cntx->my_key_dir, p_cons_cntx->pubkey_name);
        DBG_PRINT (DBG_JSON, DBG_INFO, (void *)"my_pubkey_path (%s)\n", p_cons_cntx->my_pubkey_path);
    }
    
    return (ret);
}

//
static char *json_node_path(void)
{
    char *p_cfg_path = (char *)NODE_CFG_PATH;

    DBG_PRINT (DBG_APP, DBG_INFO, (void *)"NODE_CFG_PATH : %s\n", p_cfg_path);

    return (p_cfg_path);
}

static char *json_rrnet_path(void)
{
    char *p_cfg_path = (char *)RRNET_CFG_PATH;

    DBG_PRINT (DBG_APP, DBG_INFO, (void *)"RRNET_CFG_PATH : %s\n", p_cfg_path);

    return (p_cfg_path);
}

//
#if defined(USE_JSONC)
uint32_t jsonc_cons_rr_net_chk_ver(void)
{
    uint32_t revision = 0;

    uint32_t json_len;
    char *p_json;

    json_object *p_root_obj, *p_net_obj;
    json_object *p_data;

    p_json = util_file_r(json_rrnet_path(), &json_len);

    p_root_obj = json_tokener_parse(p_json);
    
    p_net_obj = json_object_object_get(p_root_obj, "NET");

    p_data = json_object_object_get(p_net_obj, "REVISION");
    revision = json_object_get_int(p_data);

    json_object_put(p_root_obj);

    FREE_M(p_json);

    return (revision);
}
#endif // USE_JSONC

uint32_t json_cons_rr_net_chk_ver(void)
{
    uint32_t revision = 0;

#if defined(USE_JSONC)
    revision = jsonc_cons_rr_net_chk_ver();
#endif // USE_JSONC

    return (revision);
}

#if defined(USE_JSONC)
void jsonc_cons_rr_net_update(void)
{
    CONS_CNTX_T *p_cons_cntx = cons_get_cntx();
    P2P_CNTX_T *p_p2p_cntx = p2p_get_cntx();

    uint32_t json_len;
    char *p_json;

    json_object *p_root_obj, *p_net_obj;
    json_object *p_net_tier_arr, *p_net_tier_obj;
    json_object *p_nn_arr, *p_nn_obj, *p_sock_obj;
    json_object *p_data;

    uint32_t tier_idx, idx;
    CONS_TIER_T *p_tier;
    
    CFG_SOCK_INFO_T cfg_sock_info;

    uint32_t revision;

    DBG_PRINT (DBG_JSON, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    if (!(p_p2p_cntx->my_node_info.node_rule & P2P_NODE_RULE_NN))
    {
        DBG_PRINT (DBG_JSON, DBG_ERROR, (void *)"This node is not NN.\n");
        return;
    }

    p_json = util_file_r(json_rrnet_path(), &json_len);

    p_root_obj = json_tokener_parse(p_json);
    
    p_net_obj = json_object_object_get(p_root_obj, "NET");

    p_data = json_object_object_get(p_net_obj, "REVISION");
    revision = json_object_get_int(p_data);
    //ASSERT_M(revision == CFG_NEXT_REVISION(p_cons_cntx->net.revision));
    
    p_cons_cntx->net.revision = revision;

    p_data = json_object_object_get(p_net_obj, "TIER_NUM");
    p_cons_cntx->net.tier_num = json_object_get_int(p_data);
    ASSERT_M(p_cons_cntx->net.tier_num <= CONS_TIER_MAX);

    p_net_tier_arr = json_object_object_get(p_net_obj, "TIER");

    DBG_PRINT (DBG_JSON, DBG_INFO, (void *)"json_object_array_length(%d)\n", json_object_array_length(p_net_tier_arr));
    
    //for (tier_idx=0; tier_idx<p_cons_cntx->net.tier_num; tier_idx++)
    for (tier_idx=0; tier_idx<p_cons_cntx->net.tier_num; tier_idx++)
    {
        p_net_tier_obj = json_object_array_get_idx(p_net_tier_arr, tier_idx);
        p_tier = &p_cons_cntx->net.tier[tier_idx];

        p_tier->blk_gen_interval = 0;

		p_data = json_object_object_get(p_net_tier_obj, "GEN_SUB_INTRVL");
        p_tier->blk_gen_sub_intrvl = json_object_get_int(p_data);

        p_data = json_object_object_get(p_net_tier_obj, "GEN_ROUND_CNT");
        p_tier->blk_gen_round_cnt = json_object_get_int(p_data);

        p_data = json_object_object_get(p_net_tier_obj, "START_TIME");
        p_tier->blk_gen_start_time = strtoll(json_object_get_string(p_data), NULL, 0);
        DBG_PRINT (DBG_JSON, DBG_INFO, (void *)"blk_gen_start_time (%llu)\n", p_tier->blk_gen_start_time);

        p_data = json_object_object_get(p_net_tier_obj, "START_BLOCK");
        p_tier->blk_gen_start_block = strtoll(json_object_get_string(p_data), NULL, 0);
        DBG_PRINT (DBG_JSON, DBG_INFO, (void *)"blk_gen_start_block (0x%016llX)\n", p_tier->blk_gen_start_block);

        p_data = json_object_object_get(p_net_tier_obj, "TOTAL_NN");
        p_tier->nn_gen_seq.total_nn = json_object_get_int(p_data);
        DBG_PRINT (DBG_JSON, DBG_INFO, (void *)"total_nn (%d)\n", p_tier->nn_gen_seq.total_nn);

        ASSERT_M(p_tier->nn_gen_seq.total_nn > 0);

        p_nn_arr = json_object_object_get(p_net_tier_obj, "NN_LIST");
        for (idx=0; idx<p_tier->nn_gen_seq.total_nn; idx++)
        {
            p_nn_obj = json_object_array_get_idx(p_nn_arr, idx);
            
            //My Infirmation
            p_tier->nn_gen_seq.root[idx].actived = false;

            // NN P2P Address
            p_data = json_object_object_get(p_nn_obj, "P2P");
            sscanf(json_object_get_string(p_data), "0x%lX", &p_tier->nn_gen_seq.root[idx].nn_p2p_addr);

            // NN Subnet Information
            p_sock_obj = json_object_object_get(p_nn_obj, "SOCK");
            //
            p_data = json_object_object_get(p_sock_obj, "PROTO");
            p_tier->nn_gen_seq.root[idx].subnet.proto_type = json_object_get_int(p_data);
            //
            p_data = json_object_object_get(p_sock_obj, "IP");
            STRCPY_M(cfg_sock_info.ip, json_object_get_string(p_data));
            //
            p_data = json_object_object_get(p_sock_obj, "PORT");
            cfg_sock_info.port = json_object_get_int(p_data);
            //
            p_tier->nn_gen_seq.root[idx].subnet.ip = inet_addr((char *) cfg_sock_info.ip);
            p_tier->nn_gen_seq.root[idx].subnet.port = cfg_sock_info.port;
            p_tier->nn_gen_seq.root[idx].subnet.sockfd = -1;
            
            DBG_PRINT (DBG_JSON, DBG_INFO, (void *)"NN[%d] P2P Address(0x%016llX)\n", idx, p_tier->nn_gen_seq.root[idx].nn_p2p_addr);
            DBG_PRINT (DBG_JSON, DBG_INFO, (void *)"SUBNET[%d](%s) IP (0x%08X) PORT(%d)\n", idx,
                                    (p_tier->nn_gen_seq.root[idx].subnet.proto_type == CONS_TCP_TYPE)?"TCP":"UDP",
                                    p_tier->nn_gen_seq.root[idx].subnet.ip, 
                                    p_tier->nn_gen_seq.root[idx].subnet.port);

            if (IS_MY_SUBNET_ADDR(p_tier->nn_gen_seq.root[idx].nn_p2p_addr, p_p2p_cntx->my_cluster_root))
            {
                p_tier->nn_gen_seq.root[idx].actived = true;
                
                if(idx == 0)
                {
                    p_data = json_object_object_get(p_net_tier_obj, "GEN_INTERVAL");
                    p_tier->blk_gen_interval = json_object_get_int(p_data);
                }

                p_tier->nn_gen_seq.my_root_nn_idx = idx;
                p_tier->nn_gen_seq.my_prev_nn_idx = PRV_IDX(idx, p_tier->nn_gen_seq.total_nn);
                p_tier->nn_gen_seq.my_next_nn_idx = NXT_IDX(idx, p_tier->nn_gen_seq.total_nn);

                DBG_PRINT (DBG_JSON, DBG_INFO, (void *)"my_root_nn_idx(%d) my_prev_nn_idx(%d) my_next_nn_idx(%d)\n", 
                                        p_tier->nn_gen_seq.my_root_nn_idx, p_tier->nn_gen_seq.my_prev_nn_idx, p_tier->nn_gen_seq.my_next_nn_idx);

                cons_rr_net_set_blk_num();
            }
        }
    }

    json_object_put(p_root_obj);
    
    FREE_M(p_json);
}
#endif // USE_JSONC

static void json_cons_rr_net_update(void)
{
#if defined(USE_JSONC)
    jsonc_cons_rr_net_update();
#endif // USE_JSONC
}

void json_cons_rr_update(void)
{
    json_cons_rr_net_update();
}

void json_cons_rr_reinit(void)
{
    CONS_CNTX_T *p_cons_cntx = cons_get_cntx();
    
    DBG_PRINT (DBG_JSON, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    MEMSET_M(&p_cons_cntx->net, 0x00, sizeof(CONS_NET_T));
}

#if defined(USE_JSONC)
void jsonc_cons_udpate_key_info(char *p_path_str)
{
    CONS_CNTX_T *p_cons_cntx = cons_get_cntx();

    uint32_t json_len;
    char *p_json;

    json_object *p_root_obj, *p_node_obj;
    json_object *p_cons_obj, *p_path_obj;
    json_object *p_data;

    DBG_PRINT (DBG_JSON, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    p_json = util_file_r(p_path_str, &json_len);

    p_root_obj = json_tokener_parse(p_json);
    
    p_node_obj = json_object_object_get(p_root_obj, "NODE");
    p_cons_obj = json_object_object_get(p_node_obj, "CONS");

    //
    p_path_obj = json_object_object_get(p_cons_obj, "KEY_PATH");
    
    //
    p_data = json_object_object_get(p_path_obj, "PRIKEY_NAME");
    STRCPY_M(p_cons_cntx->prikey_name, json_object_get_string(p_data));
    //
    p_data = json_object_object_get(p_path_obj, "PUBKEY_NAME");
    STRCPY_M(p_cons_cntx->pubkey_name, json_object_get_string(p_data));
    //
    p_data = json_object_object_get(p_path_obj, "KEY");
    STRCPY_M(p_cons_cntx->key_dir, json_object_get_string(p_data));
    DBG_PRINT (DBG_JSON, DBG_INFO, (void *)"key_dir (%s)\n", p_cons_cntx->key_dir);
    //
    p_data = json_object_object_get(p_path_obj, "MY_KEY");
    STRCPY_M(p_cons_cntx->my_key_dir, json_object_get_string(p_data));

    sprintf(p_cons_cntx->my_prikey_path, "%s%s", p_cons_cntx->my_key_dir, p_cons_cntx->prikey_name);
    DBG_PRINT (DBG_JSON, DBG_INFO, (void *)"my_prikey_path (%s)\n", p_cons_cntx->my_prikey_path);

    sprintf(p_cons_cntx->my_pubkey_path, "%s%s", p_cons_cntx->my_key_dir, p_cons_cntx->pubkey_name);
    DBG_PRINT (DBG_JSON, DBG_INFO, (void *)"my_pubkey_path (%s)\n", p_cons_cntx->my_pubkey_path);

    json_object_put(p_root_obj);
    
    FREE_M(p_json);
}
#endif // USE_JSONC

void json_cons_udpate_key_info(char *p_path_str)
{
#if defined(USE_JSONC)
    jsonc_cons_udpate_key_info(p_path_str);
#endif // USE_JSONC
}

void json_cons_udpate(void)
{
//    json_cons_udpate_key_info(json_node_path());
    json_path_update();

    //
    cons_set_prikey_enc();

    //
    cons_set_my_pubkey();
}

void json_cons_reinit(void)
{
    CONS_CNTX_T *p_cons_cntx = cons_get_cntx();

    cons_peer_del_all();

    p_cons_cntx->b_enc_prikey = false;
    MEMSET_M(p_cons_cntx->pubkey_name, 0x00, CONS_PK_NAME_SIZE);
    MEMSET_M(p_cons_cntx->prikey_name, 0x00, CONS_PK_NAME_SIZE);
    MEMSET_M(p_cons_cntx->key_dir, 0x00, CONS_DIR_SIZE);
    MEMSET_M(p_cons_cntx->my_key_dir, 0x00, CONS_DIR_SIZE);
    MEMSET_M(p_cons_cntx->my_prikey_path, 0x00, CONS_PATH_SIZE);
    MEMSET_M(p_cons_cntx->my_pubkey_path, 0x00, CONS_PATH_SIZE);
    MEMSET_M(p_cons_cntx->my_comp_pubkey, 0x00, COMP_PUBKEY_SIZE);
}

#if defined(USE_JSONC)
void jsonc_p2p_update_info(void *pv_p2p_cntx, char *p_path_str)
{
    P2P_CNTX_T *p_p2p_cntx = (P2P_CNTX_T *)pv_p2p_cntx;

    uint32_t json_len;
    char *p_json;

    json_object *p_root_obj, *p_node_obj;
    json_object *p_p2p_obj, *p_cluster_obj;
    json_object *p_data;

    char tmp_buf[CFG_TMP_BUF_SIZE];
    uint16_t sub_addr = 0;

    DBG_PRINT (DBG_JSON, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    p_json = util_file_r(p_path_str, &json_len);

    p_root_obj = json_tokener_parse(p_json);
    
    p_node_obj = json_object_object_get(p_root_obj, "NODE");
    p_p2p_obj = json_object_object_get(p_node_obj, "P2P");

    //
    p_cluster_obj = json_object_object_get(p_p2p_obj, "CLUSTER");

    //
    p_data = json_object_object_get(p_cluster_obj, "ROOT");
    STRCPY_M(tmp_buf, json_object_get_string(p_data));
    util_str2hex_temp(tmp_buf, (uint8_t *)&p_p2p_cntx->my_cluster_root, P2P_ADDR_LEN, true);

    //
    p_data = json_object_object_get(p_cluster_obj, "ADDR");
    STRCPY_M(tmp_buf, json_object_get_string(p_data));
    util_str2hex_temp(tmp_buf, (uint8_t *)&sub_addr, P2P_ADDR_SUB_LEN, true);
    DBG_PRINT (DBG_JSON, DBG_INFO, (void *)"sub_addr (%s) (0x%04X)\n", tmp_buf, sub_addr);

    p_p2p_cntx->my_p2p_addr.u64 = p_p2p_cntx->my_cluster_root + sub_addr;
    p_p2p_cntx->my_uniq_addr = P2P_GET_UNIQ_KEY(p_p2p_cntx->my_p2p_addr.u64);

    DBG_PRINT (DBG_JSON, DBG_INFO, (void *)"my_p2p_addr (0x%016llX)\n", p_p2p_cntx->my_p2p_addr.u64);

    //
    p_p2p_cntx->my_enc_type = P2P_GRP_HDR_ENC_DISABLED;

    json_object_put(p_root_obj);
    
    FREE_M(p_json);
}
#endif // USE_JSONC

static void json_p2p_update_info(void *pv_p2p_cntx, char *p_path_str)
{
#if defined(USE_JSONC)
    jsonc_p2p_update_info(pv_p2p_cntx, p_path_str);
#endif // USE_JSONC
}

void json_p2p_udpate(void *pv_p2p_cntx)
{
    json_p2p_update_info(pv_p2p_cntx, json_node_path());
}

void json_p2p_reinit(void)
{
    P2P_CNTX_T *p_p2p_cntx = p2p_get_cntx();

    p_p2p_cntx->my_cluster_root = P2P_NULL_ADDR;
    p_p2p_cntx->my_uniq_addr = 0;
    p_p2p_cntx->my_p2p_addr.u64 = P2P_NULL_ADDR;
    p_p2p_cntx->my_p2p_data_sn = 0;
    p_p2p_cntx->my_p2p_cmd_sn = 0;
    
    //
    p_p2p_cntx->my_enc_type = P2P_GRP_HDR_ENC_DISABLED;
}

#if defined(USE_JSONC)
void jsonc_socket_update_udp_server(void *pv_sock_cntx, char *p_path_str)
{
    SOCK_CNTX_T *p_sock_cntx = (SOCK_CNTX_T *)pv_sock_cntx;
    
    CFG_SOCK_INFO_T cfg_sock_info;
    char cfg_str[CFG_STR_SIZE];
    uint32_t cnt;

    uint32_t json_len;
    char *p_json;

    json_object *p_root_obj, *p_node_obj;
    json_object *p_sock_obj;
    json_object *p_sock_num_obj, *p_sock_info_obj;
    json_object *p_data;

    DBG_PRINT (DBG_JSON, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    
    p_json = util_file_r(p_path_str, &json_len);

    p_root_obj = json_tokener_parse(p_json);
    
    p_node_obj = json_object_object_get(p_root_obj, "NODE");
    p_sock_obj = json_object_object_get(p_node_obj, "SOCK");

    //
    p_sock_num_obj = json_object_object_get(p_sock_obj, "NUM");

    //
    p_data = json_object_object_get(p_sock_num_obj, "UDP_SVR");
    p_sock_cntx->udp_svr_num = json_object_get_int(p_data);
    DBG_PRINT (DBG_JSON, DBG_INFO, (void *)"udp_svr_num (%d)\n", p_sock_cntx->udp_svr_num);

    //
    for (cnt=0; cnt<p_sock_cntx->udp_svr_num; cnt++)
    {
        MEMSET_M(&cfg_sock_info, 0x00, sizeof(CFG_SOCK_INFO_T));

        //
        sprintf(cfg_str, "UDP_SVR_%d", cnt+1);
        p_sock_info_obj = json_object_object_get(p_sock_obj, cfg_str);

        //
        p_data = json_object_object_get(p_sock_info_obj, "MREQ_IP");
        STRCPY_M(cfg_sock_info.mreq_ip, json_object_get_string(p_data));
        //
        p_data = json_object_object_get(p_sock_info_obj, "IP");
        STRCPY_M(cfg_sock_info.ip, json_object_get_string(p_data));
        //
        p_data = json_object_object_get(p_sock_info_obj, "PORT");
        cfg_sock_info.port = json_object_get_int(p_data);

        p_sock_cntx->udp_svr_sock[cnt].local.mreq_ip_addr = inet_addr((char *) cfg_sock_info.mreq_ip);

        p_sock_cntx->udp_svr_sock[cnt].local.ip_addr = inet_addr((char *) cfg_sock_info.ip);
        p_sock_cntx->udp_svr_sock[cnt].local.port = cfg_sock_info.port;

        DBG_PRINT(DBG_JSON, DBG_INFO, (void *)"UDP_SVR_%d MREQ IP(0x%08X) LOCAL IP(0x%08X) PORT(%d)\n", 
                        cnt+1, 
                        ntohl(p_sock_cntx->udp_svr_sock[cnt].local.mreq_ip_addr), 
                        ntohl(p_sock_cntx->udp_svr_sock[cnt].local.ip_addr), 
                        p_sock_cntx->udp_svr_sock[cnt].local.port);
    }

    json_object_put(p_root_obj);

    FREE_M(p_json);
}
#endif // USE_JSONC

void json_socket_update_udp_server(void *pv_sock_cntx, char *p_path_str)
{
#if defined(USE_JSONC)
    jsonc_socket_update_udp_server(pv_sock_cntx, p_path_str);
#endif // USE_JSONC
}

#if defined(USE_JSONC)
void jsonc_socket_update_udp_client(void *pv_sock_cntx, char *p_path_str)
{
    SOCK_CNTX_T *p_sock_cntx = (SOCK_CNTX_T *)pv_sock_cntx;

    CFG_SOCK_INFO_T cfg_sock_info;
    char cfg_str[CFG_STR_SIZE];
    uint32_t cnt;

    uint32_t json_len;
    char *p_json;

    json_object *p_root_obj, *p_node_obj;
    json_object *p_sock_obj;
    json_object *p_sock_num_obj, *p_sock_info_obj;
    json_object *p_peer_obj, *p_local_obj;
    json_object *p_data;

    DBG_PRINT (DBG_JSON, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    
    p_json = util_file_r(p_path_str, &json_len);

    p_root_obj = json_tokener_parse(p_json);
    
    p_node_obj = json_object_object_get(p_root_obj, "NODE");
    p_sock_obj = json_object_object_get(p_node_obj, "SOCK");

    //
    p_sock_num_obj = json_object_object_get(p_sock_obj, "NUM");

    //
    p_data = json_object_object_get(p_sock_num_obj, "UDP_CLI");
    p_sock_cntx->udp_cli_num = json_object_get_int(p_data);
    DBG_PRINT (DBG_JSON, DBG_INFO, (void *)"udp_cli_num (%d)\n", p_sock_cntx->udp_cli_num);

    //
    for (cnt=0; cnt<p_sock_cntx->udp_cli_num; cnt++)
    {
        //
        MEMSET_M(&cfg_sock_info, 0x00, sizeof(CFG_SOCK_INFO_T));

        //
        sprintf(cfg_str, "UDP_CLI_%d", cnt+1);
        p_sock_info_obj = json_object_object_get(p_sock_obj, cfg_str);

        // Peer
        p_peer_obj = json_object_object_get(p_sock_info_obj, "PEER");
        //
        p_data = json_object_object_get(p_peer_obj, "IP");
        STRCPY_M(cfg_sock_info.ip, json_object_get_string(p_data));
        //
        p_data = json_object_object_get(p_peer_obj, "PORT");
        cfg_sock_info.port = json_object_get_int(p_data);

        p_sock_cntx->udp_cli_sock[cnt].peer_svr.ip_addr = inet_addr((char *) cfg_sock_info.ip);
        p_sock_cntx->udp_cli_sock[cnt].peer_svr.port = cfg_sock_info.port;

        DBG_PRINT(DBG_JSON, DBG_INFO, (void *)"UDP_CLI_%d PEER_SVR IP(0x%08X) PORT(%d)\n", 
                        cnt+1, 
                        ntohl(p_sock_cntx->udp_cli_sock[cnt].peer_svr.ip_addr), 
                        p_sock_cntx->udp_cli_sock[cnt].peer_svr.port);

        // Local
        p_local_obj = json_object_object_get(p_sock_info_obj, "LOCAL");
        //
        p_data = json_object_object_get(p_local_obj, "IP");
        STRCPY_M(cfg_sock_info.ip, json_object_get_string(p_data));
        //
        p_data = json_object_object_get(p_local_obj, "PORT");
        cfg_sock_info.port = json_object_get_int(p_data);

        p_sock_cntx->udp_cli_sock[cnt].local.ip_addr = inet_addr((char *) cfg_sock_info.ip);
        p_sock_cntx->udp_cli_sock[cnt].local.port = cfg_sock_info.port;

        DBG_PRINT(DBG_JSON, DBG_INFO, (void *)"UDP_CLI_%d LOCAL IP(0x%08X) PORT(%d)\n", 
                        cnt+1, 
                        ntohl(p_sock_cntx->udp_cli_sock[cnt].local.ip_addr), 
                        p_sock_cntx->udp_cli_sock[cnt].local.port);
    }

    json_object_put(p_root_obj);
    
    FREE_M(p_json);
}
#endif // USE_JSONC
void json_socket_update_udp_client(void *pv_sock_cntx, char *p_path_str)
{
#if defined(USE_JSONC)
    jsonc_socket_update_udp_client(pv_sock_cntx, p_path_str);
#endif // USE_JSONC
}

#if defined(USE_JSONC)
void jsonc_socket_update_tcp_server(void *pv_sock_cntx, char *p_path_str)
{
    SOCK_CNTX_T *p_sock_cntx = (SOCK_CNTX_T *)pv_sock_cntx;
    
    CFG_SOCK_INFO_T cfg_sock_info;
    char cfg_str[CFG_STR_SIZE];
    uint32_t cnt;

    uint32_t json_len;
    char *p_json;

    json_object *p_root_obj, *p_node_obj;
    json_object *p_sock_obj;
    json_object *p_sock_num_obj, *p_sock_info_obj;
    json_object *p_cli_arr, *p_cli_obj;
    json_object *p_data;

    DBG_PRINT (DBG_JSON, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    
    p_json = util_file_r(p_path_str, &json_len);

    p_root_obj = json_tokener_parse(p_json);
    
    p_node_obj = json_object_object_get(p_root_obj, "NODE");
    p_sock_obj = json_object_object_get(p_node_obj, "SOCK");

    //
    p_sock_num_obj = json_object_object_get(p_sock_obj, "NUM");

    //
    p_data = json_object_object_get(p_sock_num_obj, "TCP_SVR");
    p_sock_cntx->tcp_svr_num = json_object_get_int(p_data);
    DBG_PRINT (DBG_JSON, DBG_INFO, (void *)"tcp_svr_num (%d)\n", p_sock_cntx->tcp_svr_num);

    //
    for (cnt=0; cnt<p_sock_cntx->tcp_svr_num; cnt++)
    {
        MEMSET_M(&cfg_sock_info, 0x00, sizeof(CFG_SOCK_INFO_T));

        //
        sprintf(cfg_str, "TCP_SVR_%d", cnt+1);
        p_sock_info_obj = json_object_object_get(p_sock_obj, cfg_str);

        //
        p_data = json_object_object_get(p_sock_info_obj, "IP");
        STRCPY_M(cfg_sock_info.ip, json_object_get_string(p_data));
        //
        p_data = json_object_object_get(p_sock_info_obj, "PORT");
        cfg_sock_info.port = json_object_get_int(p_data);

        p_sock_cntx->tcp_svr_sock[cnt].local.ip_addr = inet_addr((char *) cfg_sock_info.ip);
        p_sock_cntx->tcp_svr_sock[cnt].local.port = cfg_sock_info.port;

        //
        p_data = json_object_object_get(p_sock_info_obj, "TOTAL_PEERS");
        p_sock_cntx->tcp_svr_sock[cnt].peer_cli_num = json_object_get_int(p_data);
        ASSERT_M (p_sock_cntx->tcp_svr_sock[cnt].peer_cli_num <= SOCK_ADDR_MAX);

        uint32_t cli_idx;
        char cli_ip[IP_STR_SIZE];

        p_cli_arr = json_object_object_get(p_sock_info_obj, "PEERS");
        
        for (cli_idx=0; cli_idx<p_sock_cntx->tcp_svr_sock[cnt].peer_cli_num; cli_idx++)
        {
            p_cli_obj = json_object_array_get_idx(p_cli_arr, cli_idx);

            //
            p_data = json_object_object_get(p_cli_obj, "IP");
            STRCPY_M(cli_ip, json_object_get_string(p_data));
            p_sock_cntx->tcp_svr_sock[cnt].peer_cli[cli_idx].ip_addr = inet_addr((char *) cli_ip);
            //
            p_data = json_object_object_get(p_cli_obj, "PORT");
            p_sock_cntx->tcp_svr_sock[cnt].peer_cli[cli_idx].port = json_object_get_int(p_data);

            DBG_PRINT(DBG_JSON, DBG_INFO, (void *)"TCP_SVR_%d PEER CLI[%d] IP(0x%08X) PORT(%d)\n", 
                            cnt+1, cli_idx,
                            ntohl(p_sock_cntx->tcp_svr_sock[cnt].peer_cli[cli_idx].ip_addr),
                            p_sock_cntx->tcp_svr_sock[cnt].peer_cli[cli_idx].port);
        }

        DBG_PRINT(DBG_JSON, DBG_INFO, (void *)"TCP_SVR_%d LOCAL IP(0x%08X) PORT(%d)\n", 
                        cnt+1, 
                        ntohl(p_sock_cntx->tcp_svr_sock[cnt].local.ip_addr), 
                        p_sock_cntx->tcp_svr_sock[cnt].local.port);
    }

    json_object_put(p_root_obj);
    
    FREE_M(p_json);
}
#endif // USE_JSONC

void json_socket_update_tcp_server(void *pv_sock_cntx, char *p_path_str)
{
#if defined(USE_JSONC)
    jsonc_socket_update_tcp_server(pv_sock_cntx, p_path_str);
#endif // USE_JSONC
}

#if defined(USE_JSONC)
void jsonc_socket_update_tcp_client(void *pv_sock_cntx, char *p_path_str)
{
    SOCK_CNTX_T *p_sock_cntx = (SOCK_CNTX_T *)pv_sock_cntx;

    CFG_SOCK_INFO_T cfg_sock_info;
    char cfg_str[CFG_STR_SIZE];
    uint32_t cnt;

    uint32_t json_len;
    char *p_json;

    json_object *p_root_obj, *p_node_obj;
    json_object *p_sock_obj;
    json_object *p_sock_num_obj, *p_sock_info_obj;
    json_object *p_peer_obj, *p_local_obj;
    json_object *p_data;

    DBG_PRINT (DBG_JSON, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    
    p_json = util_file_r(p_path_str, &json_len);

    p_root_obj = json_tokener_parse(p_json);
    
    p_node_obj = json_object_object_get(p_root_obj, "NODE");
    p_sock_obj = json_object_object_get(p_node_obj, "SOCK");

    //
    p_sock_num_obj = json_object_object_get(p_sock_obj, "NUM");

    //
    p_data = json_object_object_get(p_sock_num_obj, "TCP_CLI");
    p_sock_cntx->tcp_cli_num = json_object_get_int(p_data);
    DBG_PRINT (DBG_JSON, DBG_INFO, (void *)"tcp_cli_num (%d)\n", p_sock_cntx->tcp_cli_num);

    //
    for (cnt=0; cnt<p_sock_cntx->tcp_cli_num; cnt++)
    {
        MEMSET_M(&cfg_sock_info, 0x00, sizeof(CFG_SOCK_INFO_T));

        //
        sprintf(cfg_str, "TCP_CLI_%d", cnt+1);
        p_sock_info_obj = json_object_object_get(p_sock_obj, cfg_str);

        //
        p_data = json_object_object_get(p_sock_info_obj, "AUTO_JOIN");
        cfg_sock_info.auto_join = json_object_get_int(p_data);
        //
        p_data = json_object_object_get(p_sock_info_obj, "P2P_JOIN");
        cfg_sock_info.p2p_join = json_object_get_int(p_data);

        p_sock_cntx->tcp_cli_sock[cnt].auto_join = cfg_sock_info.auto_join;
        p_sock_cntx->tcp_cli_sock[cnt].p2p_join = cfg_sock_info.p2p_join;

        DBG_PRINT(DBG_JSON, DBG_INFO, (void *)"TCP_CLI_%d AUTO_JOIN(%d) P2P_JOIN(%d)\n", 
                        cnt+1, 
                        p_sock_cntx->tcp_cli_sock[cnt].auto_join,
                        p_sock_cntx->tcp_cli_sock[cnt].p2p_join);

        // Peer
        p_peer_obj = json_object_object_get(p_sock_info_obj, "PEER");
        //
        p_data = json_object_object_get(p_peer_obj, "IP");
        STRCPY_M(cfg_sock_info.ip, json_object_get_string(p_data));
        //
        p_data = json_object_object_get(p_peer_obj, "PORT");
        cfg_sock_info.port = json_object_get_int(p_data);

        p_sock_cntx->tcp_cli_sock[cnt].peer_svr.ip_addr = inet_addr((char *) cfg_sock_info.ip);
        p_sock_cntx->tcp_cli_sock[cnt].peer_svr.port = cfg_sock_info.port;

        DBG_PRINT(DBG_JSON, DBG_INFO, (void *)"TCP_CLI_%d PEER IP(0x%08X) PORT(%d)\n", 
                        cnt+1, 
                        ntohl(p_sock_cntx->tcp_cli_sock[cnt].peer_svr.ip_addr), 
                        p_sock_cntx->tcp_cli_sock[cnt].peer_svr.port);

        // Local
        p_local_obj = json_object_object_get(p_sock_info_obj, "LOCAL");
        //
        p_data = json_object_object_get(p_local_obj, "IP");
        STRCPY_M(cfg_sock_info.ip, json_object_get_string(p_data));
        //
        p_data = json_object_object_get(p_local_obj, "PORT");
        cfg_sock_info.port = json_object_get_int(p_data);

        p_sock_cntx->tcp_cli_sock[cnt].local.ip_addr = inet_addr((char *) cfg_sock_info.ip);
        p_sock_cntx->tcp_cli_sock[cnt].local.port = cfg_sock_info.port;

        DBG_PRINT(DBG_JSON, DBG_INFO, (void *)"TCP_CLI_%d LOCAL IP(0x%08X) PORT(%d)\n", 
                        cnt+1, 
                        ntohl(p_sock_cntx->tcp_cli_sock[cnt].local.ip_addr), 
                        p_sock_cntx->tcp_cli_sock[cnt].local.port);
    }

    json_object_put(p_root_obj);
    
    FREE_M(p_json);
}
#endif // USE_JSONC

void json_socket_update_tcp_client(void *pv_sock_cntx, char *p_path_str)
{
#if defined(USE_JSONC)
    jsonc_socket_update_tcp_client(pv_sock_cntx, p_path_str);
#endif // USE_JSONC
}

#if (SOCK_FIREWALLD == ENABLED)
void json_socket_update_fwd(void *pv_sock_cntx)
{
    SOCK_CNTX_T *p_sock_cntx = (SOCK_CNTX_T *)pv_sock_cntx;
    uint32_t cnt, idx;

    // firewall-cmd init
    util_init_fwd();

    DBG_PRINT(DBG_JSON, DBG_INFO, (void *)"tcp_svr_num[%d]\n", p_sock_cntx->tcp_svr_num);

    for (cnt=0; cnt<p_sock_cntx->tcp_svr_num; cnt++)
    {
        DBG_PRINT(DBG_JSON, DBG_INFO, (void *)"TCP[%d] : peer_cli_num[%d]\n", cnt, p_sock_cntx->tcp_svr_sock[cnt].peer_cli_num);
        
        for(idx=0; idx<p_sock_cntx->tcp_svr_sock[cnt].peer_cli_num; idx++)
        {
            DBG_PRINT(DBG_JSON, DBG_INFO, (void *)"TCP[%d][%d] : peer_cli IP(0x%08X) PORT(%d)\n", 
                            cnt, idx, 
                            ntohl(p_sock_cntx->tcp_svr_sock[cnt].peer_cli[idx].ip_addr), 
                            p_sock_cntx->tcp_svr_sock[cnt].peer_cli[idx].port);
            
            //util_update_fwd_source(p_sock_cntx->tcp_svr_sock[cnt].peer_cli[idx].ip_addr);
            //util_update_fwd_source_port(p_sock_cntx->tcp_svr_sock[cnt].peer_cli[idx].port, true);
            
            util_update_fwd_rich_rule(p_sock_cntx->tcp_svr_sock[cnt].peer_cli[idx].ip_addr, p_sock_cntx->tcp_svr_sock[cnt].peer_cli[idx].port, 
                                        p_sock_cntx->tcp_svr_sock[cnt].local.ip_addr, p_sock_cntx->tcp_svr_sock[cnt].local.port, true);
        }
    }

    DBG_PRINT(DBG_JSON, DBG_INFO, (void *)"udp_svr_num[%d]\n", p_sock_cntx->udp_svr_num);

    for (cnt=0; cnt<p_sock_cntx->udp_svr_num; cnt++)
    {
        DBG_PRINT(DBG_JSON, DBG_INFO, (void *)"UDP[%d] : peer_cli_num[%d]\n", cnt, p_sock_cntx->udp_svr_sock[cnt].peer_cli_num);
        
        for(idx=0; idx<p_sock_cntx->udp_svr_sock[cnt].peer_cli_num; idx++)
        {
            DBG_PRINT(DBG_JSON, DBG_INFO, (void *)"UDP[%d][%d] : peer_cli IP(0x%08X) PORT(%d)\n", 
                            cnt, idx, 
                            ntohl(p_sock_cntx->udp_svr_sock[cnt].peer_cli[idx].ip_addr), 
                            p_sock_cntx->udp_svr_sock[cnt].peer_cli[idx].port);
            
            //util_update_fwd_source(p_sock_cntx->udp_svr_sock[cnt].peer_cli[idx].ip_addr);
            //util_update_fwd_source_port(p_sock_cntx->udp_svr_sock[cnt].peer_cli[idx].port, false);

            util_update_fwd_rich_rule(p_sock_cntx->udp_svr_sock[cnt].peer_cli[idx].ip_addr, p_sock_cntx->udp_svr_sock[cnt].peer_cli[idx].port, 
                                        p_sock_cntx->udp_svr_sock[cnt].local.ip_addr, p_sock_cntx->udp_svr_sock[cnt].local.port, false);
        }
    }

    // firewall-cmd reload
    util_reload_fwd();
}
#endif // SOCK_FIREWALLD

static void json_socket_update_info(void *pv_sock_cntx, char *p_path_str)
{
    DBG_PRINT (DBG_JSON, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    // UDP Server
    json_socket_update_udp_server(pv_sock_cntx, p_path_str);

    // UDP Client
    json_socket_update_udp_client(pv_sock_cntx, p_path_str);
    
    // TCP Server
    json_socket_update_tcp_server(pv_sock_cntx, p_path_str);
    
    // TCP Client
    json_socket_update_tcp_client(pv_sock_cntx, p_path_str);

#if (SOCK_FIREWALLD == ENABLED)
    json_socket_update_fwd(pv_sock_cntx);
#endif // SOCK_FIREWALLD
}

void json_socket_udpate(void *pv_sock_cntx)
{
    json_socket_update_info(pv_sock_cntx, json_node_path());
}

void json_socket_reinit(void *pv_sock_cntx)
{
    sock_close((SOCK_CNTX_T *)pv_sock_cntx);
    sock_delete((SOCK_CNTX_T *)pv_sock_cntx);
}

#if defined(USE_JSONC)
void jsonc_node_info_update(void)
{
    P2P_CNTX_T *p_p2p_cntx = p2p_get_cntx();

    uint32_t json_len;
    char *p_json;
    
    json_object *p_root_obj, *p_node_obj;
    json_object *p_data;

    char tmp_buf[CFG_TMP_BUF_SIZE];

    DBG_PRINT (DBG_JSON, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    p_json = util_file_r(json_node_path(), &json_len);

    p_root_obj = json_tokener_parse(p_json);
    
    p_node_obj = json_object_object_get(p_root_obj, "NODE");

    //
    p_data = json_object_object_get(p_node_obj, "RULE");
    STRCPY_M(tmp_buf, json_object_get_string(p_data));

    if (!STRCMP_M(tmp_buf, "NN"))
    {
        p_p2p_cntx->my_node_info.node_type = P2P_NODE_TYPE_RN;
        p_p2p_cntx->my_node_info.node_rule = P2P_NODE_RULE_NN;
    }
    else
    {
        ASSERT_M(0);
    }
    
    DBG_PRINT (DBG_JSON, DBG_INFO, (void *)"node_rule (%s)\n", tmp_buf);

    json_object_put(p_root_obj);
    
    FREE_M(p_json);
}
#endif // USE_JSONC

void json_node_info_update(void)
{
#if defined(USE_JSONC)
    jsonc_node_info_update();
#endif // USE_JSONC
}

void json_node_info_reinit(void)
{
    P2P_CNTX_T *p_p2p_cntx = p2p_get_cntx();

    p_p2p_cntx->my_node_info.node_type = 0;
    p_p2p_cntx->my_node_info.node_rule = 0;
}

void json_reinit(void *pv_sock_cntx)
{
    DBG_PRINT (DBG_JSON, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    
    //Reinit node.json
    json_socket_reinit(pv_sock_cntx);
    
    json_p2p_reinit();
    
    json_cons_reinit();
    json_cons_rr_reinit();

    json_node_info_reinit();
}

static char *json_db_path(void)
{
    char *p_cfg_path = (char *)DB_CFG_PATH;

    DBG_PRINT (DBG_APP, DBG_INFO, (void *)"DB_CFG_PATH : %s\n", p_cfg_path);

    return (p_cfg_path);
}

#if defined(USE_JSONC)
int32_t jsonc_db_update(void)
{
    P2P_CNTX_T     *p_p2p_cntx     = NULL;
    DB_CONN_INFO_T *p_db_conn_info = NULL;

    uint32_t json_len;
    char *p_json;

    json_object *p_root_obj, *p_db_obj;
    json_object *p_data;

    char           srv_type_str[8], sql_type_str[30];

    p_p2p_cntx      = p2p_get_cntx();
    p_db_conn_info  = db_get_conn_info();

    DBG_PRINT (DBG_JSON, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    switch (p_p2p_cntx->my_node_info.node_rule)
    {
        case P2P_NODE_RULE_NN:   { snprintf(srv_type_str, 8, "NN");  } break;
        default: { ASSERT_M(0); } break;
    }

    p_json = util_file_r(json_db_path(), &json_len);

    p_root_obj = json_tokener_parse(p_json);
    
    p_db_obj = json_object_object_get(p_root_obj, srv_type_str);

    //
    p_data = json_object_object_get(p_db_obj, "TYPE");
    STRCPY_M(sql_type_str, json_object_get_string(p_data));

    if (!strcasecmp(sql_type_str, "mongodb"))
    {
        p_db_conn_info->db_type  = DB_TYPE_MONGODB;
    }
    else if (!strcasecmp(sql_type_str, "mysql"))
    {
        p_db_conn_info->db_type  = DB_TYPE_MYSQL;
    }
    else
    {
        DBG_PRINT (DBG_JSON, DBG_ERROR, (void *)"Unknown type db(%s)\n", sql_type_str);
        ASSERT_M(0);

        json_object_put(p_root_obj);

        FREE_M(p_json);

        return (ERROR_); 
    }

    //
    p_data = json_object_object_get(p_db_obj, "HOST");
    snprintf(p_db_conn_info->db_host, DB_CONN_STRING_LEN, "%s", json_object_get_string(p_data));
    //
    p_data = json_object_object_get(p_db_obj, "PORT");
    p_db_conn_info->db_port  = json_object_get_int(p_data);
    //
    p_data = json_object_object_get(p_db_obj, "DB");
    snprintf(p_db_conn_info->db_name, DB_CONN_STRING_LEN, "%s", json_object_get_string(p_data));
    //
    p_data = json_object_object_get(p_db_obj, "USER");
    snprintf(p_db_conn_info->db_user, DB_CONN_STRING_LEN, "%s", json_object_get_string(p_data));
    //
#if 0
    uint8_t *p_pw;
    uint32_t pw_len;

    p_pw = openssl_aes_decrypt_pw(NULL, NULL, &pw_len);
    DBG_PRINT(DBG_DB, DBG_INFO, (void *)"PASSWORD : %s\n", p_pw);
    STRCPY_M(p_db_conn_info->db_pw, (char *)p_pw);
#else
    p_data = json_object_object_get(p_db_obj, "PASSWORD");
    snprintf(p_db_conn_info->db_pw, DB_CONN_STRING_LEN, "%s", json_object_get_string(p_data));
#endif
    //
    p_data = json_object_object_get(p_db_obj, "PW_PATH");
    snprintf(p_db_conn_info->db_pw_path, DB_CONN_STRING_LEN, "%s", json_object_get_string(p_data));
    //
    p_data = json_object_object_get(p_db_obj, "SEED_PATH");
    snprintf(p_db_conn_info->db_seed_path, DB_CONN_STRING_LEN, "%s", json_object_get_string(p_data));
    //
    p_data = json_object_object_get(p_db_obj, "SOCKET");
    snprintf(p_db_conn_info->db_sock, DB_CONN_STRING_LEN, "%s", json_object_get_string(p_data));

    p_db_conn_info->init = DB_CONN_INIT_OK;

    json_object_put(p_root_obj);
    
    FREE_M(p_json);

    return (SUCCESS_);
}
#endif // USE_JSONC

int32_t json_db_update(void)
{
    int32_t ret;

#if defined(USE_JSONC)
    ret = jsonc_db_update();
#endif // USE_JSONC
    
    return (ret);
}

#if (CLI_SERIAL_EMULATOR == ENABLED)
static char *json_cli_cfg_path(void)
{
    char *p_cfg_path = (char *)CLI_CFG_PATH;

    DBG_PRINT (DBG_APP, DBG_INFO, (void *)"CLI_CFG_PATH : %s\n", p_cfg_path);

    return (p_cfg_path);
}
#endif // CLI_SERIAL_EMULATOR

//
#if defined(USE_JSONC)
void jsonc_cli_udpate(void *pv_cli_cntx)
{
#if (CLI_SERIAL_EMULATOR == ENABLED)
    CLI_CNTX_T *p_cli_cntx = (CLI_CNTX_T *)pv_cli_cntx;

    uint32_t json_len;
    char *p_json;

    json_object *p_root_obj, *p_cli_obj;
    json_object *p_emul_obj, *p_path_obj;
    json_object *p_data;

    p_json = util_file_r(json_cli_cfg_path(), &json_len);

    p_root_obj = json_tokener_parse(p_json);
    p_cli_obj = json_object_object_get(p_root_obj, "CLI");

    p_emul_obj = json_object_object_get(p_cli_obj, "SERIAL_EMUL");
    p_path_obj = json_object_object_get(p_emul_obj, "PATH");

    p_data = json_object_object_get(p_path_obj, "TTY_0");
    STRCPY_M(p_cli_cntx->cli_tty_0_path, json_object_get_string(p_data));
    p_data = json_object_object_get(p_path_obj, "TTY_1");
    STRCPY_M(p_cli_cntx->cli_tty_1_path, json_object_get_string(p_data));

    json_object_put(p_root_obj);
    
    FREE_M(p_json);
#endif // CLI_SERIAL_EMULATOR
}
#endif // USE_JSONC

void json_cli_udpate(void *pv_cli_cntx)
{
#if (CLI_SERIAL_EMULATOR == ENABLED)
    CLI_CNTX_T *p_cli_cntx = (CLI_CNTX_T *)pv_cli_cntx;

#if defined(USE_JSONC)
    jsonc_cli_udpate(pv_cli_cntx);
#endif // USE_JSONC

    DBG_PRINT (DBG_LUA, DBG_INFO, (void *)"cli_tty_0_path (%s)\n", p_cli_cntx->cli_tty_0_path);
    DBG_PRINT (DBG_LUA, DBG_INFO, (void *)"cli_tty_1_path (%s)\n", p_cli_cntx->cli_tty_1_path);
#endif // CLI_SERIAL_EMULATOR
}


