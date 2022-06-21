/**
    @file db_redis.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

// http://redisgate.kr/redis/clients/hiredis_async.php

#include "global.h"

#if defined (USE_LIBAE)
/* Put event loop in the global scope, so it can be explicitly stopped */
static aeEventLoop *p_loop;
#elif defined (USE_LIBEVENT) // libevent
static struct event_base *p_base;
#elif defined (USE_LIBEV) // libev
static struct ev_loop *loop;
#endif // USE_LIBAE

#if (REDIS_PUBSUB_CHECK == ENABLED)
static bool gb_sub_actived = true;
#endif // REDIS_PUBSUB_CHECK

redisAsyncContext *ac_tx_ack_pub, *ac_blk_noti_pub, *ac_ctrl_noti_ack_pub, *ac_tx_sub, *ac_ctrl_sub;

pthread_mutex_t redis_mutex = PTHREAD_MUTEX_INITIALIZER;

char g_redis_channel[REDIS_PUBSUB_MAX][REDIS_CHANNEL_NAME_MAX_LEN] = {"txs", "txAcks", "blkNoti", "ctrlNoti", "ctrlNotiAcks"};

static void redis_sub_ctrl_cmd_cb(redisAsyncContext *c, void *r, void *cmd)
{
	redisReply *reply = (redisReply *)r;
    
	if (reply == NULL)
    {
    	DBG_PRINT(DBG_DB, DBG_ERROR, (void *)"(%s) Error: Reply is null, [%s]\n", __FUNCTION__, (char*)cmd);
    	return;
    }
    
	if (reply->type == REDIS_REPLY_ERROR)
    {
    	DBG_PRINT(DBG_DB, DBG_ERROR, (void *)"(%s) Error: %s, [%s]\n", __FUNCTION__, reply->str, (char*)cmd);
    	return;
    }

    pthread_mutex_lock(&redis_mutex);

    if(reply->type == REDIS_REPLY_ARRAY && reply->elements == 3) 
    {
        if(STRCMP_M(reply->element[0]->str, "subscribe") != SUCCESS_)
        {
            // subscribe message
            // reply->element[0]->str == "message", reply->element[1]==topic name,
            // reply->element[2]->str == data

            DBG_PRINT(DBG_DB, DBG_NONE, (void *)"(%s) : %s -> %s\n", __FUNCTION__, reply->element[1]->str, (uint8_t *)reply->element[2]->str);

            if(STRCMP_M(reply->element[1]->str, (const char *)g_redis_channel[REDIS_PUBSUB_SUB_CTRL]) == SUCCESS_)
            {
                char *argv[REDIS_CONS_CMD_ARG_MAX] = { NULL, };
                //char *ack_msg = NULL;
                char ack_msg[100] = {0, };

                int argc = 0;

                char *ptr = strtok(reply->element[2]->str, " ");

                while(ptr != NULL) {
                    argv[argc] = ptr;
                    DBG_PRINT(DBG_DB, DBG_NONE, (void *)"%s\n", argv[argc]);
                    argc++;
                    ptr = strtok(NULL, " ");
                }

                if(STRCMP_M( argv[0], "rr") == 0) 
                {
                    if(argc < 2)
                    {
                        DBG_PRINT(DBG_DB, DBG_ERROR, (void *)"Error : %s - argc(%d)\r\n", argv[0], argc);
                        return;
                    }

                    if(STRCMP_M( argv[1], "update") == 0)
                    {
                        json_cons_rr_update();
                        STRCPY_M(ack_msg, (char *)"rr update complete");
                    }
                    else if(STRCMP_M( argv[1], "next") == 0)
                    {
                        cons_rr_net_set_next_nn();
                        STRCPY_M(ack_msg, (char *)"rr next complete");
                    }
                    else if(STRCMP_M( argv[1], "start") == 0)
                    {
                        cons_rr_blk_gen_start();
                        STRCPY_M(ack_msg, (char *)"rr start complete");
                    }
                    else if(STRCMP_M( argv[1], "restart") == 0)
                    {
                        cons_rr_set_blk_gen_stop(CONS_BLK_GEN_STOP_DISABLED);
                        cons_timer_tx_stop(0);
                        STRCPY_M(ack_msg, (char *)"rr start complete");
                    }
                    else if(STRCMP_M( argv[1], "stop") == 0)
                    {
                        cons_rr_set_blk_gen_stop(CONS_BLK_GEN_STOP_BY_IS);
                        STRCPY_M(ack_msg, (char *)"rr stop complete");
                    }
                }
                else if(STRCMP_M( argv[0], "leave") == 0)
                {
                    if(argc < 2)
                    {
                        DBG_PRINT(DBG_DB, DBG_ERROR, (void *)"Error : %s - argc(%d)\r\n", argv[0], argc);
                    }

                    if(STRCMP_M( argv[1], "all") == 0)
                    {
                        STRCPY_M(ack_msg, (char *)"leave all complete");
                    }
                }
                else if(STRCMP_M( argv[0], "re") == 0)
                {
                    if(argc < 2)
                    {
                        DBG_PRINT(DBG_DB, DBG_ERROR, (void *)"Error : %s - argc(%d)\r\n", argv[0], argc);                        
                    }

                    if(STRCMP_M( argv[1], "init") == 0) // Remove node.json, rr_net.json, rr_subnet.json
                    {
                        json_reinit(p2p_sock_cntx());
                        STRCPY_M(ack_msg, (char *)"re init complete");
                    }
                    else if(STRCMP_M( argv[1], "run") == 0) // Parse node.json
                    {
                        P2P_CNTX_T *p_p2p_cntx;
                        
                        p2p_init(false);
                        cons_init(false);

                        p_p2p_cntx = p2p_get_cntx();

                        if(p_p2p_cntx->my_node_info.node_rule & P2P_NODE_RULE_NN)
                        {
                            STRCPY_M(ack_msg, (char *)"NN start");
                        }                    
                    }
                }

                if (STRLEN_M(ack_msg))
                {
                    DBG_PRINT(DBG_DB, DBG_NONE, (void *)"ack_len[%d], ack_msg [%s]\n", STRLEN_M(ack_msg), ack_msg);
#if (REDIS_SUB_TX_NEW == ENABLED)
                    int32_t msg_len;
                
                    msg_len = STRLEN_M(ack_msg) + 1;
                    task_send_msg(&db_redis_task_pool, &db_redis_task_list, (uint8_t *)ack_msg, msg_len, false, DB_REDIS_TASK_MSG_EVENT_04);
#else
                    redis_pub_ctrl_acks((const char *)ack_msg);
#endif // REDIS_SUB_TX_NEW
                }
            }
        }
    }

    pthread_mutex_unlock(&redis_mutex);
}

#if (REDIS_SUB_TX == ENABLED)
static void redis_sub_tx_cmd_cb(redisAsyncContext *c, void *r, void *cmd) {
	redisReply *reply = (redisReply *)r;
    
	if (reply == NULL)
    {
    	DBG_PRINT(DBG_DB, DBG_ERROR, (void *)"(%s) Error: Reply is null, [%s]\n", __FUNCTION__, (char*)cmd);
    	return;
    }
    
	if (reply->type == REDIS_REPLY_ERROR)
    {
    	DBG_PRINT(DBG_DB, DBG_ERROR, (void *)"(%s) Error: %s, [%s]\n", __FUNCTION__, reply->str, (char*)cmd);
    	return;
    }

    pthread_mutex_lock(&redis_mutex);

    if(reply->type == REDIS_REPLY_ARRAY && reply->elements == 3) 
    {
        if(STRCMP_M(reply->element[0]->str, "subscribe") != SUCCESS_)
        {
            // subscribe message
            // reply->element[0]->str == "message", reply->element[1]==topic name,
            // reply->element[2]->str == data

            DBG_PRINT(DBG_DB, DBG_NONE, (void *)"(%s) : %s -> %s\n", __FUNCTION__, reply->element[1]->str, (uint8_t *)reply->element[2]->str);

            if(STRCMP_M(reply->element[1]->str, (const char *)g_redis_channel[REDIS_PUBSUB_SUB_TX]) == SUCCESS_)
            {
                int32_t ret = ERROR_;
                
                CONS_TX_INFO_T *p_tx_info;
                uint32_t tx_info_cnt, tx_info_len;

                uint32_t cnt = 0;

                char *p_tx_info_str;
                uint32_t tx_info_str_len;

                p_tx_info_str = reply->element[2]->str;
                tx_info_str_len = STRLEN_M(p_tx_info_str);

                DBG_PRINT(DBG_DB, DBG_INFO, (void *)"Redis Subscribe Transactions : tx_info_str_len(%d)\n", tx_info_str_len);

                tx_info_cnt = tx_info_str_len / TX_STR_SIZE;
                tx_info_len = sizeof(CONS_TX_INFO_T) * tx_info_cnt;
                DBG_PRINT(DBG_DB, DBG_NONE, (void *)"TxCnt : %d, TxLen : %d\n", tx_info_cnt, tx_info_len);

                p_tx_info = (CONS_TX_INFO_T *) MALLOC_M(tx_info_len);

                util_str2hex_temp((const char *)p_tx_info_str, (uint8_t *)p_tx_info, tx_info_len, false);

                for(cnt = 0; cnt < tx_info_cnt; cnt++) 
                {
                    MEMCPY_REV2(&p_tx_info[cnt].db_key, DB_KEY_SIZE);

                    DBG_PRINT(DBG_DB, DBG_NONE, (void *)"db_key[%d] = 0x%016llX\n", cnt, p_tx_info[cnt].db_key);
                    DBG_DUMP(DBG_DB, DBG_NONE, (void *)"sc_hash dump \n", (const uint8_t *)p_tx_info[cnt].sc_hash, HASH_SIZE);
                }
#if (REDIS_SUB_TX_NEW == ENABLED)
                uint32_t msg_event;

                msg_event = DB_REDIS_TASK_MSG_EVENT_01;
                ret = task_send_msg(&db_redis_task_pool, &db_redis_task_list, (uint8_t *)p_tx_info, tx_info_len, false, msg_event);
#else
                ret = cons_send_tx(cnt, p_tx_info);
#endif // REDIS_SUB_TX_NEW
                if (ret == ERROR_)
                {
                    // 
                }
#if (REDIS_SUB_TX_NEW == ENABLED)
                FREE_M(p_tx_info);
#else
                //
#endif // REDIS_SUB_TX_NEW
            }
        }
    }

    pthread_mutex_unlock(&redis_mutex);
}
#endif // REDIS_SUB_TX

#if (REDIS_PUBSUB_CHECK == ENABLED)
static void redis_pubsub_cmd_cb(redisAsyncContext *c, void *r, void *cmd)
{
	redisReply *reply = (redisReply *)r;
    
	if (reply == NULL)
    {
    	DBG_PRINT(DBG_DB, DBG_ERROR, (void *)"(%s) Error: Reply is null, [%s]\n", __FUNCTION__, (char*)cmd);
    	return;
    }
    
	if (reply->type == REDIS_REPLY_ERROR)
    {
    	DBG_PRINT(DBG_DB, DBG_ERROR, (void *)"(%s) Error: %s, [%s]\n", __FUNCTION__, reply->str, (char*)cmd);
    	return;
    }

    pthread_mutex_lock(&redis_mutex);

    if (STRCMP_M((char *)cmd, "PUBSUB") == SUCCESS_ && reply->elements == 2)
    {
        gb_sub_actived = true;
        
        if (reply->element[1]->integer == 0)
        {
            // No Subscribers
            // PRINT ERROR
            DBG_PRINT(DBG_DB, DBG_ERROR, (void *)"Redis Have No Subscribers Channel [%s]\n", reply->element[0]->str);
            // process exit
//            exit(1);
            gb_sub_actived = false;
        }
    }
    else 
    {
        DBG_PRINT(DBG_DB, DBG_TRACE, (void *)"%s -> %s\n", (char *)cmd, reply->str);
    }

    pthread_mutex_unlock(&redis_mutex);
}
#endif // REDIS_PUBSUB_CHECK

static void redis_pub_blk_noti_cb(redisAsyncContext *c, void *r, void *cmd)
{
    redisReply *reply = (redisReply *)r;

    if (reply == NULL)
    {
    	DBG_PRINT(DBG_DB, DBG_ERROR, (void *)"(%s) Error: Reply is null, [%s]\n", __FUNCTION__, (char*)cmd);
    	return;
    }
    
	if (reply->type == REDIS_REPLY_ERROR)
    {
    	DBG_PRINT(DBG_DB, DBG_ERROR, (void *)"(%s) Error: %s, [%s]\n", __FUNCTION__, reply->str, (char*)cmd);
    	return;
    }

    if (STRCMP_M((char *)cmd, "PUBLISH") == SUCCESS_)
    {
        DBG_PRINT(DBG_DB, DBG_INFO, (void *)"(%s) success\n", __FUNCTION__);
        return;
    }
}

static void redis_pub_tx_ack_cb(redisAsyncContext *c, void *r, void *cmd)
{
    redisReply *reply = (redisReply *)r;

    if (reply == NULL)
    {
    	DBG_PRINT(DBG_DB, DBG_ERROR, (void *)"(%s) Error: Reply is null, [%s]\n", __FUNCTION__, (char*)cmd);
    	return;
    }
    
	if (reply->type == REDIS_REPLY_ERROR)
    {
    	DBG_PRINT(DBG_DB, DBG_ERROR, (void *)"(%s) Error: %s, [%s]\n", __FUNCTION__, reply->str, (char*)cmd);
    	return;
    }

    if (STRCMP_M((char *)cmd, "PUBLISH") == SUCCESS_)
    {
        DBG_PRINT(DBG_DB, DBG_INFO, (void *)"(%s) success\n", __FUNCTION__);;
        return;
    }
}

static void redis_pub_ctrl_ack_cb(redisAsyncContext *c, void *r, void *cmd)
{
    redisReply *reply = (redisReply *)r;

    if (reply == NULL)
    {
    	DBG_PRINT(DBG_DB, DBG_ERROR, (void *)"(%s) Error: Reply is null, [%s]\n", __FUNCTION__, (char*)cmd);
    	return;
    }
    
	if (reply->type == REDIS_REPLY_ERROR)
    {
    	DBG_PRINT(DBG_DB, DBG_ERROR, (void *)"(%s) Error: %s, [%s]\n", __FUNCTION__, reply->str, (char*)cmd);
    	return;
    }

    if (STRCMP_M((char *)cmd, "PUBLISH") == SUCCESS_)
    {
        DBG_PRINT(DBG_DB, DBG_INFO, (void *)"(%s) success\n", __FUNCTION__);;
        return;
    }
}


static void redis_conn(void)
{
    char *ip = (char *)"127.0.0.1";
	int port = 6379;

	signal(SIGPIPE, SIG_IGN);

    pthread_mutex_lock(&redis_mutex);
    
    // Redis Async Connection
    ac_tx_ack_pub = redisAsyncConnect(ip, port);
    ac_blk_noti_pub = redisAsyncConnect(ip, port);
    ac_ctrl_noti_ack_pub = redisAsyncConnect(ip, port);
    ac_tx_sub = redisAsyncConnect(ip, port);
    ac_ctrl_sub = redisAsyncConnect(ip, port);

    pthread_mutex_unlock(&redis_mutex);
}

static void redis_disconn(void)
{
    pthread_mutex_lock(&redis_mutex);

    redisAsyncFree(ac_tx_ack_pub);
    redisAsyncFree(ac_blk_noti_pub);
    redisAsyncFree(ac_ctrl_noti_ack_pub);
    redisAsyncFree(ac_tx_sub);
    redisAsyncFree(ac_ctrl_sub);

    pthread_mutex_unlock(&redis_mutex);
}

static void redis_conn_cb(const redisAsyncContext *ac, int status) {
	if (status != REDIS_OK) {
    	DBG_PRINT(DBG_DB, DBG_TRACE, (void *)"%s:%i -> %s\n", ac->c.tcp.host, ac->c.tcp.port, ac->errstr);
    	return;
    }
	DBG_PRINT(DBG_DB, DBG_TRACE, (void *)"%s:%i -> Connection OK\n", ac->c.tcp.host, ac->c.tcp.port);
}

static void redis_disconn_cb(const redisAsyncContext *c, int status) {
    if (status != REDIS_OK) {
        DBG_PRINT(DBG_DB, DBG_TRACE, (void *)"Error: %s\n", c->errstr);
        return;
    }
    DBG_PRINT(DBG_DB, DBG_TRACE, (void *)"Disconnected...\n");
}

static void redis_attach(void)
{
    pthread_mutex_lock(&redis_mutex);
    
#if defined (USE_LIBAE)
	p_loop = aeCreateEventLoop(1024);

    redisAeAttach(p_loop, ac_tx_ack_pub);
    redisAeAttach(p_loop, ac_blk_noti_pub);
    redisAeAttach(p_loop, ac_ctrl_noti_ack_pub);
    redisAeAttach(p_loop, ac_tx_sub);
    redisAeAttach(p_loop, ac_ctrl_sub);
#elif defined (USE_LIBEV) // libev
    loop = ev_default_loop(0);

    redisLibevAttach(EV_A_ ac_tx_ack_pub);
    redisLibevAttach(EV_A_ ac_blk_noti_pub);
    redisLibevAttach(EV_A_ ac_ctrl_noti_ack_pub);
    redisLibevAttach(EV_A_ ac_tx_sub);
    redisLibevAttach(EV_A_ ac_ctrl_sub);
#elif defined (USE_LIBEVENT) // libevent
    p_base = event_base_new();

    redisLibeventAttach(ac_tx_ack_pub, p_base);
    redisLibeventAttach(ac_blk_noti_pub, p_base);
    redisLibeventAttach(ac_ctrl_noti_ack_pub, p_base);
    redisLibeventAttach(ac_tx_sub, p_base);
    redisLibeventAttach(ac_ctrl_sub, p_base);
#endif // USE_LIBAE

    pthread_mutex_unlock(&redis_mutex);
}

static void redis_cb_reg(void)
{
    uint8_t *p_pw;
    uint32_t pw_len;
    
    p_pw = openssl_aes_decrypt_pw((char *)"./../../conf/pw/db/me/seed", (char *)"./../../conf/pw/db/me/pw_redis.fin", &pw_len);
//    DBG_PRINT(DBG_DB, DBG_ERROR, (void *)"redis PW : (%s)\n", p_pw);

    pthread_mutex_lock(&redis_mutex);

	redisAsyncSetConnectCallback(ac_tx_ack_pub, redis_conn_cb);
    redisAsyncSetDisconnectCallback(ac_tx_ack_pub, redis_disconn_cb);

    redisAsyncSetConnectCallback(ac_blk_noti_pub, redis_conn_cb);
    redisAsyncSetDisconnectCallback(ac_blk_noti_pub, redis_disconn_cb);

    redisAsyncSetConnectCallback(ac_ctrl_noti_ack_pub, redis_conn_cb);
    redisAsyncSetDisconnectCallback(ac_ctrl_noti_ack_pub, redis_disconn_cb);

	redisAsyncSetConnectCallback(ac_tx_sub, redis_conn_cb);
    redisAsyncSetDisconnectCallback(ac_tx_sub,redis_disconn_cb);

    redisAsyncSetConnectCallback(ac_ctrl_sub, redis_conn_cb);
    redisAsyncSetDisconnectCallback(ac_ctrl_sub, redis_disconn_cb);

    // AsyncCommand
    redisAsyncCommand(ac_tx_ack_pub, redis_pub_tx_ack_cb, (void *)"AUTH", (const char *)"AUTH %s", (const char *)p_pw);
	redisAsyncCommand(ac_tx_ack_pub, redis_pub_tx_ack_cb, (void *)"PING", (const char *)"PING");

    redisAsyncCommand(ac_blk_noti_pub, redis_pub_blk_noti_cb, (void *)"AUTH", (const char *)"AUTH %s", (const char *)p_pw);
    redisAsyncCommand(ac_blk_noti_pub, redis_pub_blk_noti_cb, (void *)"PING", (const char *)"PING");

    redisAsyncCommand(ac_ctrl_noti_ack_pub, redis_pub_ctrl_ack_cb, (void *)"AUTH", (const char *)"AUTH %s", (const char *)p_pw);
    redisAsyncCommand(ac_ctrl_noti_ack_pub, redis_pub_ctrl_ack_cb, (void *)"PING", (const char *)"PING");

#if (REDIS_SUB_TX == ENABLED)
    redisAsyncCommand(ac_tx_sub, redis_sub_tx_cmd_cb, (void *)"AUTH", (const char *)"AUTH %s", (const char *)p_pw);
	redisAsyncCommand(ac_tx_sub, redis_sub_tx_cmd_cb, (void *)"PING", (const char *)"PING");
#endif // REDIS_SUB_TX

    redisAsyncCommand(ac_ctrl_sub, redis_sub_ctrl_cmd_cb, (void *)"AUTH", (const char *)"AUTH %s", (const char *)p_pw);
    redisAsyncCommand(ac_ctrl_sub, redis_sub_ctrl_cmd_cb, (void *)"PING", (const char *)"PING");

    pthread_mutex_unlock(&redis_mutex);

    FREE_M(p_pw);
}

static void redis_reg_sub(void)
{
    pthread_mutex_lock(&redis_mutex);

#if (REDIS_SUB_TX == ENABLED)
    P2P_CNTX_T *p_p2p_cntx = p2p_get_cntx();

    if (p_p2p_cntx->my_node_info.node_rule & P2P_NODE_RULE_NN)
    {
        redisAsyncCommand(ac_tx_sub, redis_sub_tx_cmd_cb, (void *)"SUBSCRIBE", (const char *)"SUBSCRIBE %s", (const char *)g_redis_channel[REDIS_PUBSUB_SUB_TX]);
    }
#endif // REDIS_SUB_TX

    redisAsyncCommand(ac_ctrl_sub, redis_sub_ctrl_cmd_cb, (void *)"SUBSCRIBE", (const char *)"SUBSCRIBE %s", (const char *)g_redis_channel[REDIS_PUBSUB_SUB_CTRL]);

    pthread_mutex_unlock(&redis_mutex);
}

static void redis_run(void)
{
#if defined (USE_LIBAE)
    aeMain(p_loop);
#elif defined (USE_LIBEV) // libev
    ev_loop(loop, 0);
#elif defined (USE_LIBEVENT) // libevent
    //event_base_dispatch(p_base);
    event_base_loop(p_base, EVLOOP_NONBLOCK);
#endif // USE_LIBAE
}

// Publish
#if (REDIS_SUB_TX == ENABLED)
void redis_pub_tx_ack(CONS_TX_ACK_INFO_T *p_tx_ack)
{
#if (REDIS_SUB_TX_NEW == ENABLED)
    // uint32_t len_str;
    uint32_t pos;
    uint32_t idx;
    int32_t len;
    char *p_tx_ack_str;

    DBG_PRINT(DBG_DB, DBG_NONE, (void *)"(%s)\n", __FUNCTION__);

#if (REDIS_PUBSUB_CHECK == ENABLED)
    if (gb_sub_actived == false)
    {
        return;
    }
#endif // REDIS_PUBSUB_CHECK

    len = BLK_NUM_STR_SIZE + (p_tx_ack->cnt * (DB_KEY_STR_DATA_SIZE)) + 1;
    DBG_PRINT(DBG_DB, DBG_NONE, (void *)"len [%d]\n", len);
    
    p_tx_ack_str = (char *)MALLOC_M(len);

    DBG_PRINT(DBG_DB, DBG_NONE, (void *)"blk_num(0x%016llX)\n", p_tx_ack->blk_num);
    
    pos = 0;
    
    util_hex2str_temp((uint8_t *)&p_tx_ack->blk_num, BLK_NUM_SIZE, &p_tx_ack_str[pos], BLK_NUM_STR_SIZE, true);
    pos += BLK_NUM_STR_DATA_SIZE;
    
    for(idx = 0; idx < p_tx_ack->cnt; idx++)
    {
        DBG_PRINT(DBG_DB, DBG_NONE, (void *)"db_key[%d](0x%016llX)\n", idx, p_tx_ack->db_key[idx]);
        util_hex2str_temp((uint8_t *)&p_tx_ack->db_key[idx], DB_KEY_SIZE, &p_tx_ack_str[pos], DB_KEY_STR_SIZE, true);
        pos += DB_KEY_STR_DATA_SIZE;
    }

    p_tx_ack_str[pos] = '\0';
#else
    uint32_t idx;
    uint32_t pos = 0;
    int32_t hex_str_blk_num_len = BLK_NUM_STR_SIZE;
    int32_t hex_str_db_key_len = DB_KEY_STR_SIZE;
    int32_t len;

    U64_U u64_blk_num;
    U64_U u64_db_key;

    char hex_str_blk_num[BLK_NUM_STR_SIZE];
    char hex_str_db_key[DB_KEY_STR_SIZE];
    char *p_tx_ack_str;

    DBG_PRINT(DBG_DB, DBG_NONE, (void *)"(%s)\n", __FUNCTION__);

#if (REDIS_PUBSUB_CHECK == ENABLED)
    if (gb_sub_actived == false)
    {
        return;
    }
#endif // REDIS_PUBSUB_CHECK

    len = BLK_NUM_STR_SIZE + (p_tx_ack->cnt * (DB_KEY_STR_DATA_SIZE));
    DBG_PRINT(DBG_DB, DBG_NONE, (void *)"len [%d]\n", len);
    
    p_tx_ack_str = (char *)MALLOC_M(len);

    u64_blk_num.u64 = p_tx_ack->blk_num;
    //MEMCPY_REV2(u64_blk_num.u8, BLK_NUM_SIZE);

    DBG_DUMP(DBG_DB, DBG_NONE, (void *)"blk_num \n", (const uint8_t *)u64_blk_num.u8, BLK_NUM_SIZE);

    util_hex2str((uint8_t *)u64_blk_num.u8, BLK_NUM_SIZE, hex_str_blk_num, &hex_str_blk_num_len);

    DBG_PRINT(DBG_DB, DBG_NONE, (void *)"str_blk_num [%s]\n", hex_str_blk_num);

    MEMCPY_M(p_tx_ack_str, hex_str_blk_num, BLK_NUM_STR_DATA_SIZE);
    pos += BLK_NUM_STR_DATA_SIZE;

    for(idx = 0; idx < p_tx_ack->cnt; idx++) 
    {
        u64_db_key.u64 = p_tx_ack->db_key[idx];
        MEMCPY_REV2(u64_db_key.u8, DB_KEY_SIZE);
        util_hex2str((uint8_t *)u64_db_key.u8, DB_KEY_SIZE, hex_str_db_key, &hex_str_db_key_len);

        DBG_PRINT(DBG_DB, DBG_NONE, (void *)"str_db_key [%s]\n", hex_str_db_key);
        DBG_PRINT(DBG_DB, DBG_NONE, (void *)"db_key(0x%016llX)\n", u64_db_key.u64);

        MEMCPY_M(p_tx_ack_str + pos, hex_str_db_key, DB_KEY_STR_DATA_SIZE);
        pos += DB_KEY_STR_DATA_SIZE;
    }

#endif // REDIS_SUB_TX_NEW

    DBG_PRINT(DBG_DB, DBG_INFO, (void *)"tx_ack_str : [%s]\n", p_tx_ack_str);

    pthread_mutex_lock(&redis_mutex);

#if (REDIS_PUBSUB_CHECK == ENABLED)
    redisAsyncCommand(ac_tx_ack_pub, redis_pubsub_cmd_cb, (void *)"PUBSUB", (const char *)"PUBSUB NUMSUB %s", (const char *)g_redis_channel[REDIS_PUBSUB_PUB_TX_ACK]);
#endif // REDIS_PUBSUB_CHECK
    redisAsyncCommand(ac_tx_ack_pub, redis_pub_tx_ack_cb, (void *)"PUBLISH", (const char *)"PUBLISH %s %s", (const char *)g_redis_channel[REDIS_PUBSUB_PUB_TX_ACK], (const char *)p_tx_ack_str);

    FREE_M(p_tx_ack_str);
    
    pthread_mutex_unlock(&redis_mutex);
}
#endif // REDIS_SUB_TX

void redis_pub_blk_noti(CONS_LIGHT_BLK_T* p_light_blk) 
{
    uint32_t pos = 0;
    char hex_str_blk_noti_msg[BLK_NOTI_STR_SIZE];

    DBG_PRINT(DBG_DB, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

#if (REDIS_PUBSUB_CHECK == ENABLED)
    if (gb_sub_actived == false)
    {
        return;
    }
#endif // REDIS_PUBSUB_CHECK

    DBG_PRINT(DBG_DB, DBG_NONE, (void *)"blk_num [0x%016llX][%llu]\n", p_light_blk->blk_num, p_light_blk->blk_num);
    DBG_PRINT(DBG_DB, DBG_NONE, (void *)"blk_gen_time [%llu]\n", p_light_blk->bgt);
    DBG_PRINT(DBG_DB, DBG_NONE, (void *)"tx_cnt [%u]\n", p_light_blk->tx_cnt);
    DBG_DUMP(DBG_DB, DBG_NONE, (void *)"blk_hash \n", p_light_blk->blk_hash, HASH_SIZE);

    util_hex2str_temp((uint8_t *)&p_light_blk->blk_num, BLK_NUM_SIZE, &hex_str_blk_noti_msg[pos], BLK_NUM_STR_SIZE, true);
    pos += BLK_NUM_STR_DATA_SIZE;
    util_hex2str_temp((uint8_t *)&p_light_blk->bgt, BGT_SIZE, &hex_str_blk_noti_msg[pos], BGT_STR_SIZE, true);
    pos += BGT_STR_DATA_SIZE;
    util_hex2str_temp((uint8_t *)&p_light_blk->tx_cnt, TX_CNT_SIZE, &hex_str_blk_noti_msg[pos], TX_CNT_STR_SIZE, true);
    pos += TX_CNT_STR_DATA_SIZE;
    util_hex2str_temp((uint8_t *)p_light_blk->blk_hash, HASH_SIZE, &hex_str_blk_noti_msg[pos], HASH_STR_SIZE, false);
    pos += HASH_STR_DATA_SIZE;

    hex_str_blk_noti_msg[pos] = '\0';

    DBG_PRINT(DBG_DB, DBG_TRACE, (void *)"str_block_noti_msg [%s]\n", hex_str_blk_noti_msg);
    DBG_PRINT(DBG_DB, DBG_TRACE, (void *)"pos (%u)\n", pos);

    pthread_mutex_lock(&redis_mutex);

#if (REDIS_PUBSUB_CHECK == ENABLED)
    redisAsyncCommand(ac_blk_noti_pub, redis_pubsub_cmd_cb, (void *)"PUBSUB", (const char *)"PUBSUB NUMSUB %s", (const char *)g_redis_channel[REDIS_PUBSUB_PUB_BLK_NOTI]);
#endif // REDIS_PUBSUB_CHECK
    redisAsyncCommand(ac_blk_noti_pub, redis_pub_blk_noti_cb, (void *)"PUBLISH", (const char *)"PUBLISH %s %s", (const char *)g_redis_channel[REDIS_PUBSUB_PUB_BLK_NOTI], (const char *)hex_str_blk_noti_msg);

    pthread_mutex_unlock(&redis_mutex);
}

void redis_pub_ctrl_acks(const char *msg) 
{
    DBG_PRINT(DBG_DB, DBG_TRACE, (void *)"(%s) \n", __FUNCTION__);
    DBG_PRINT(DBG_DB, DBG_INFO, (void *)"ctrl_ack : %s\n", msg);

#if (REDIS_PUBSUB_CHECK == ENABLED)
    if (gb_sub_actived == false)
    {
        return;
    }
    pthread_mutex_lock(&redis_mutex);

    redisAsyncCommand(ac_ctrl_noti_ack_pub, redis_pubsub_cmd_cb, (void *)"PUBSUB", (const char *)"PUBSUB NUMSUB %s", (const char *)g_redis_channel[REDIS_PUBSUB_PUB_CTRL_ACKS]);
#endif // REDIS_PUBSUB_CHECK
    redisAsyncCommand(ac_ctrl_noti_ack_pub, redis_pub_ctrl_ack_cb, (void *)"PUBLISH", (const char *)"PUBLISH %s %s", (const char *)g_redis_channel[REDIS_PUBSUB_PUB_CTRL_ACKS], (const char *)msg);

    pthread_mutex_unlock(&redis_mutex);
}

void redis_pub_ctrl_ack_node_start(void)
{
    P2P_CNTX_T *p_p2p_cntx = p2p_get_cntx();
    char ack_msg[100] = {0, };
    
#if (REDIS_PUBSUB_CHECK == ENABLED)
    if (gb_sub_actived == false)
    {
        return;
    }
#endif // REDIS_PUBSUB_CHECK

    if (p_p2p_cntx->my_node_info.node_rule & P2P_NODE_RULE_NN)
    {
        STRCPY_M(ack_msg, (char *)"NN start");
    }
    else
    {
        return;
    }

    DBG_PRINT(DBG_DB, DBG_NONE, (void *)"ack_len[%d], ack_msg [%s]\n", STRLEN_M(ack_msg), ack_msg);
#if (REDIS_SUB_TX_NEW == ENABLED)
    int32_t msg_len;

    msg_len = STRLEN_M(ack_msg) + 1;
    task_send_msg(&db_redis_task_pool, &db_redis_task_list, (uint8_t *)ack_msg, msg_len, false, DB_REDIS_TASK_MSG_EVENT_04);
#else
    redis_pub_ctrl_acks((const char *)ack_msg);
#endif // REDIS_SUB_TX_NEW
}

void *t_redis_main(void *p_data)
{
    pid_t pid; // process id
    
    char* thread_name = (char*)p_data;
    //bool exe_thread = true;
    int task_ret = TASK_EXIT_NORMAL;

#if (defined (_WIN32) || defined (_WIN64))
    pthread_t tid; // thread id
    
    pid = GetCurrentProcessId();
    tid = pthread_self();
#else
    pid_t tid;

    pid = getpid();
    tid = syscall(SYS_gettid);

    setpriority(PRIO_PROCESS, tid, g_tid_nice[DB_REDIS_THREAD_IDX]);
#endif

    DBG_PRINT(DBG_CLI, DBG_TRACE, (void *)"%s\n", __FUNCTION__);
    DBG_PRINT(DBG_DB, DBG_INFO, (void *)"%s is started.! - pid(%d), tid(%d)\n", thread_name, pid, tid);

    //db_redis_timer_run();

    redis_conn();
    redis_attach();
    redis_cb_reg();

    redis_reg_sub();

    redis_pub_ctrl_ack_node_start();

    while(1)
    {
        db_redis_task_msg_handler();

        redis_run();
        usleep(10);
    }
    
    redis_disconn();

    pthread_exit(&task_ret);
    
    return (void *)p_data;
}

void redis_task_init(void)
{
    db_redis_task_msg_init();
}

