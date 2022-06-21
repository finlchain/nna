/**
    @file db_mysql.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

//
void mysql_get_svr_version(MYSQL *mysql)
{
    uint64_t svr_ver;

    // major_version*10000 + release_level*100 + sub_version
    svr_ver = mysql_get_server_version(mysql);
    
    DBG_PRINT(DBG_DB, DBG_INFO, (void *)"MySQL SVR Ver: %llu\n", svr_ver);
}

void mysql_get_cli_version(void)
{
    uint64_t cli_ver;

    // major_version*10000 + release_level*100 + sub_version
    cli_ver = mysql_get_client_version();
    
    DBG_PRINT(DBG_DB, DBG_INFO, (void *)"MySQL CLI Ver: %llu\n", cli_ver);
}

static void mysql_print_error(char *p_msg, const char *p_reason)
{
    if (p_reason)
    {
        DBG_PRINT(DBG_DB, DBG_ERROR, (void *)"mysql_error (%s) reason(%s)\n", p_msg, p_reason);
    }
    else
    {
        DBG_PRINT(DBG_DB, DBG_ERROR, (void *)"mysql_error (%s) reason(Unknown)\n", p_msg);
    }
}

// Init
static int32_t mysql_db_init(MYSQL *p_conn)
{
    int32_t ret = ERROR_;
    char query_buf[QUERY_MAX_SIZE] = {0x00, };

    DBG_PRINT(DBG_DB, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    get_current_rss_monitor(DBG_NONE, (char *)"1");

    if( p_conn == NULL )
    {
        DBG_PRINT(DBG_DB, DBG_ERROR, (void *)"(%s) Connection Error\n", __FUNCTION__);
        return (ret);
    }

    do
    {
#if (DB_DROP_DATABASE == ENABLED)
        sprintf(query_buf, "DROP DATABASE IF EXISTS block");
        if (mysql_query(p_conn, query_buf))
        {
            break;
        }
#endif // DB_DROP_DATABASE

        sprintf(query_buf, "CREATE DATABASE IF NOT EXISTS block");
        if (mysql_query(p_conn, query_buf))
        {
            break;
        }

        sprintf(query_buf, "USE block");
        if(mysql_query(p_conn, query_buf))
        {
            break;
        }

        sprintf(query_buf, "CREATE TABLE IF NOT EXISTS `blk_txs` "
                            "(" 
                                "`subnet_id` smallint(5) unsigned DEFAULT 0 NOT NULL, "
                                "`blk_num` bigint(20) unsigned DEFAULT 0 NOT NULL COMMENT 'Block Number', "
                                "`db_key` bigint(20) unsigned DEFAULT 0 NOT NULL COMMENT 'DB Key', "
                                "`sc_hash` text NOT NULL COMMENT 'Transaction Hash', "
                                "KEY `sc_hash` (`sc_hash`(64)) USING BTREE, "
                                "UNIQUE KEY `uk_db_key` (`db_key`, `subnet_id`), "
                                "PRIMARY KEY (`db_key`, `blk_num`, `sc_hash`(64), `subnet_id`) USING BTREE"
                            ")");
        if (mysql_query(p_conn, query_buf))
        {
            break;
        }

        sprintf(query_buf, "CREATE TABLE IF NOT EXISTS `blk_contents` "
                            "("
                                "`subnet_id` smallint(5) unsigned DEFAULT 0 NOT NULL, "
                                "`blk_num` bigint(20) unsigned DEFAULT 0 NOT NULL COMMENT 'Block Number',"
                                "`p2p_addr` bigint(20) unsigned DEFAULT 0 NOT NULL COMMENT 'BP P2PAddrss', "
                                "`bgt` bigint(20) unsigned DEFAULT 0 NOT NULL COMMENT 'Block Genration Time', "
                                "`pbh` text NOT NULL COMMENT 'Previous Block Hash', "
                                "`tx_cnt` int(11) unsigned DEFAULT 0 NOT NULL COMMENT 'Number of transaction the block has', "
                                "`blk_hash` text NOT NULL COMMENT 'Block Hash', "
                                "`sig` text NOT NULL COMMENT 'Signature of BP',"
                                "`pubkey` text NOT NULL COMMENT 'Signed Public Key',"
                                "`bct`  bigint(20) unsigned, "
                                "KEY `blk_hash` (`blk_hash`(64)) USING BTREE, "
                                "KEY `bgt` (`bgt`) USING BTREE, "
                                "UNIQUE KEY `uk_blk_num` (`blk_num`, `subnet_id`), "
                                "PRIMARY KEY (`blk_num`, `blk_hash`(64), `subnet_id`) USING BTREE"
                            ")");
        if (mysql_query(p_conn, query_buf))
        {
            break;
        }

        ret = DB_RESULT_SUCCESS;
    } while(0);

    if (ret != DB_RESULT_SUCCESS)
    {
        mysql_print_error(query_buf, mysql_error(p_conn));
        ASSERT_M(0);
    }
    
    get_current_rss_monitor(DBG_NONE, (char *)"2");
    
    return (ret);
}


DB_RESULT_E mysql_conn_init(void **pp_mgr, uint16_t mgr_cnt, char *p_db_host, uint16_t db_port, char *p_db_user, char *p_db_pw, char *p_db_name, char *p_db_sock, char *p_pw_path, char *p_seed_path)
{
    DB_RESULT_E ret = DB_RESULT_FAILURE;
    MYSQL_INST_T *p_mysql_inst;
    
    DBG_PRINT(DBG_DB, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    get_current_rss_monitor(DBG_NONE, (char *)"1");

    p_mysql_inst = (MYSQL_INST_T *)MALLOC_M(sizeof(MYSQL_INST_T));
    
    if (p_mysql_inst)
    {
        uint8_t *p_pw;
        uint32_t pw_len;

        (*pp_mgr)  = p_mysql_inst;

        p_pw = openssl_aes_decrypt_pw(p_seed_path, p_pw_path, &pw_len);
        DBG_PRINT(DBG_DB, DBG_INFO, (void *)"mysql pw : %s\n", p_pw);

        mysql_init(&p_mysql_inst->conn);
        //if( mysql_real_connect(&p_mysql_inst->conn, "localhost", "root", (char *)p_pw, NULL, 0, NULL, 0) == NULL)
        //if( mysql_real_connect(&p_mysql_inst->conn, "localhost", "root", (char *)p_pw, NULL, 0, "/disk/db/mysql/mysql.sock", 0) == NULL)
        if( mysql_real_connect(&p_mysql_inst->conn, "localhost", "root", (char *)p_pw, NULL, 0, p_db_sock, 0) == NULL)
        {
            mysql_print_error((char *)"1 mysql_real_connect", mysql_error(&p_mysql_inst->conn));
            ASSERT_M(0);
        }

        mysql_db_init(&p_mysql_inst->conn);
        
        mysql_init(&p_mysql_inst->conn_db);
        //if( mysql_real_connect(&p_mysql_inst->conn_db, "localhost", "root", (char *)p_pw, "block", 0, NULL, 0) == NULL)
        //if( mysql_real_connect(&p_mysql_inst->conn_db, "localhost", "root", (char *)p_pw, "block", 0, "/disk/db/mysql/mysql.sock", 0) == NULL)
        if( mysql_real_connect(&p_mysql_inst->conn_db, "localhost", "root", (char *)p_pw, "block", 0, p_db_sock, 0) == NULL)
        {
            mysql_print_error((char *)"2 mysql_real_connect", mysql_error(&p_mysql_inst->conn));
            ASSERT_M(0);
        }

        ret = DB_RESULT_SUCCESS;

        DB_GET_SVR_VERSION(&p_mysql_inst->conn);
        DB_GET_CLI_VERSION();

        FREE_M(p_pw);
    }
    
    get_current_rss_monitor(DBG_NONE, (char *)"2");

    return (ret);
}

void mysql_conn_close(void **pp_mgr)
{
    MYSQL_INST_T *p_mysql_inst;
    
    DBG_PRINT(DBG_DB, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    get_current_rss_monitor(DBG_NONE, (char *)"1");

    p_mysql_inst = (MYSQL_INST_T *)(*pp_mgr);
    
    if (p_mysql_inst)
    {
        mysql_close(&p_mysql_inst->conn);
        mysql_close(&p_mysql_inst->conn_db);

        FREE_M(*pp_mgr);
    }

    get_current_rss_monitor(DBG_NONE, (char *)"2");
}

DB_RESULT_E mysql_truncate(void)
{
    DB_RESULT_E ret = DB_RESULT_FAILURE;
#if (DB_TRUNCATE_TABLES == ENABLED)
    char query_buf[QUERY_MAX_SIZE] = {0x00, };

    MYSQL_INST_T *p_mysql_inst = (MYSQL_INST_T *)db_get_db_inst_mgr();
    
    DBG_PRINT(DBG_DB, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    get_current_rss_monitor(DBG_NONE, (char *)"1");

    do
    {
        sprintf(query_buf, "TRUNCATE blk_txs");
        if (mysql_query(&p_mysql_inst->conn_db, query_buf))
        {
            break;
        }
        
        sprintf(query_buf, "TRUNCATE blk_contents");
        if (mysql_query(&p_mysql_inst->conn_db, query_buf))
        {
            break;
        }

        ret = DB_RESULT_SUCCESS;
    } while(0);

    if (ret != DB_RESULT_SUCCESS)
    {
        mysql_print_error(query_buf, mysql_error(&p_mysql_inst->conn_db));
        ASSERT_M(0);
    }

    get_current_rss_monitor(DBG_NONE, (char *)"2");
#else
    ret = DB_RESULT_SUCCESS;
#endif // DB_TRUNCATE_TABLES

    return (ret);
}

// Insert Table - block DB
DB_RESULT_E mysql_insert_t_blk_tx(uint64_t blk_num, uint64_t db_key, uint8_t *p_sc_hash)
{
    MYSQL_INST_T *p_mysql_inst = (MYSQL_INST_T *)db_get_db_inst_mgr();
    char query_buf[QUERY_MAX_SIZE];

    char sc_hash_str[HASH_STR_SIZE];
    
    P2P_CNTX_T *p_p2p_cntx = p2p_get_cntx();
    uint16_t subnet_id;

    DBG_PRINT(DBG_DB, DBG_NONE, (void *)"(%s)\n", __FUNCTION__);
    get_current_rss_monitor(DBG_NONE, (char *)"1");

    subnet_id = p_p2p_cntx->my_uniq_addr;
    ASSERT_M (subnet_id == CONS_GET_SUBNET_ID(db_key));

    util_hex2str_temp(p_sc_hash, HASH_SIZE, sc_hash_str, HASH_STR_SIZE, false);

    DBG_PRINT(DBG_DB, DBG_NONE, (void *)"(%s)\n", sc_hash_str);

    sprintf(query_buf, "INSERT IGNORE INTO blk_txs VALUES(%d, %lu, %lu, '%s')", subnet_id, blk_num, db_key, sc_hash_str);
    DBG_PRINT(DBG_DB, DBG_NONE, (void *) "%s", query_buf);
    DBG_PRINT(DBG_DB, DBG_NONE, (void *) "blk_num (0x%016llX), db_key (0x%016llX)\n", blk_num, db_key);

    if(mysql_query(&p_mysql_inst->conn_db, query_buf))
    {
        mysql_print_error(query_buf, mysql_error(&p_mysql_inst->conn_db));

        return (DB_RESULT_FAILURE);
    }

    get_current_rss_monitor(DBG_NONE, (char *)"2");
    
    return (DB_RESULT_SUCCESS);
}

void *mysql_insert_t_blk_tx_start(uint32_t len)
{
    char *p_query_buf;

    // Alloc Query Buffer
    p_query_buf = (char *)MALLOC_M(len);
    ASSERT_M(p_query_buf);

    DBG_PRINT(DBG_DB, DBG_NONE, (void *)"(%s)\n", __FUNCTION__);
    get_current_rss_monitor(DBG_NONE, (char *)"1");
    
    sprintf(p_query_buf, "INSERT IGNORE INTO blk_txs VALUES");
    DBG_PRINT(DBG_DB, DBG_NONE, (void *) "%s", p_query_buf);

    get_current_rss_monitor(DBG_NONE, (char *)"2");

    return (p_query_buf);
}

DB_RESULT_E mysql_insert_t_blk_tx_process(void *p_arg, bool b_last, uint64_t blk_num, uint64_t db_key, uint8_t *p_sc_hash)
{
    int32_t len;
    char sc_hash_str[HASH_STR_SIZE];
    
    P2P_CNTX_T *p_p2p_cntx = p2p_get_cntx();
    uint16_t subnet_id;

    char *p_query_buf = (char *)p_arg;

    DBG_PRINT(DBG_DB, DBG_NONE, (void *)"(%s)\n", __FUNCTION__);
    get_current_rss_monitor(DBG_NONE, (char *)"1");

    subnet_id = p_p2p_cntx->my_uniq_addr;
    ASSERT_M (subnet_id == CONS_GET_SUBNET_ID(db_key));

    DBG_PRINT(DBG_DB, DBG_NONE, (void *)"subnet_id (0x%04X) db_key(0x%016llX)\n", subnet_id, db_key);

    util_hex2str_temp(p_sc_hash, HASH_SIZE, sc_hash_str, HASH_STR_SIZE, false);

    len = STRLEN_M(p_query_buf);

    if (b_last)
    {
        sprintf(&p_query_buf[len], "(%d, %lu, %lu,'%s')", subnet_id, blk_num, db_key, sc_hash_str);
    }
    else
    {
        sprintf(&p_query_buf[len], "(%d, %lu, %lu,'%s'),", subnet_id, blk_num, db_key, sc_hash_str);
    }
    
    DBG_PRINT(DBG_DB, DBG_NONE, (void *) "%s", &p_query_buf[len]);

    get_current_rss_monitor(DBG_NONE, (char *)"2");

    return (DB_RESULT_SUCCESS);
}

DB_RESULT_E mysql_insert_t_blk_tx_end(void *p_arg)
{
    DB_RESULT_E ret = DB_RESULT_SUCCESS;
    MYSQL_INST_T *p_mysql_inst = (MYSQL_INST_T *)db_get_db_inst_mgr();
    char *p_query_buf = (char *)p_arg;
    
    DBG_PRINT(DBG_DB, DBG_NONE, (void *)"(%s)\n", __FUNCTION__);
    get_current_rss_monitor(DBG_NONE, (char *)"1");
    
    DBG_PRINT(DBG_DB, DBG_NONE, (void *) "%s", p_query_buf);

    if(mysql_query(&p_mysql_inst->conn_db, p_query_buf))
    {
        mysql_print_error(p_query_buf, mysql_error(&p_mysql_inst->conn_db));

        ASSERT_M(0);
        ret = DB_RESULT_FAILURE;
    }

    // Free Query Buffer
    FREE_M(p_query_buf);

    get_current_rss_monitor(DBG_NONE, (char *)"2");
    
    return (ret);
}

// Insert Block
DB_RESULT_E mysql_insert_t_blk_contents(CONS_LIGHT_BLK_T *p_light_blk)
{
    MYSQL_INST_T *p_mysql_inst = (MYSQL_INST_T *)db_get_db_inst_mgr();
    char query_buf[QUERY_MAX_SIZE];
    
    char prv_hash_str[HASH_STR_SIZE], hash_str[HASH_STR_SIZE];
    char sig_str[SIG_STR_SIZE];
    char pubkey_str[COMP_PUBKEY_STR_SIZE];
    
    uint16_t subnet_id;
#if (CONS_USE_SUBNET_ID == ENABLED)
    subnet_id = CONS_GET_SUBNET_ID(p_light_blk->blk_num);
#else
    P2P_CNTX_T *p_p2p_cntx = p2p_get_cntx();

    subnet_id = p_p2p_cntx->my_uniq_addr;
#endif // CONS_USE_SUBNET_ID

    DBG_PRINT(DBG_DB, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    get_current_rss_monitor(DBG_NONE, (char *)"1");

    //DBG_PRINT(DBG_DB, DBG_INFO, (void *)"gen_p2p_addr (0x%016llX), my_p2p_addr (0x%016llX)\n", p2p_addr, p_p2p_cntx->my_p2p_addr.u64);

    util_hex2str_temp(p_light_blk->blk_hash, HASH_SIZE, hash_str, HASH_STR_SIZE, false);
    DBG_PRINT(DBG_DB, DBG_NONE, (void *)"hash_str : (%s)\n", hash_str);
    
    //util_hex2str(prev_hash_buf, HASH_SIZE, prev_hash_str_buf, &len);
    util_hex2str_temp(p_light_blk->pbh, HASH_SIZE, prv_hash_str, HASH_STR_SIZE, false);
    DBG_PRINT(DBG_DB, DBG_NONE, (void *)"prv_hash_str : (%s)\n", prv_hash_str);

    util_hex2str_temp(p_light_blk->sig, SIG_SIZE, sig_str, SIG_STR_SIZE, false);
    DBG_PRINT(DBG_DB, DBG_NONE, (void *)"sig_str : (%s)\n", sig_str);

    util_hex2str_temp(p_light_blk->sig_pubkey, COMP_PUBKEY_SIZE, pubkey_str, COMP_PUBKEY_STR_SIZE, false);
    DBG_PRINT(DBG_DB, DBG_NONE, (void *)"sig_pubkey_str : (%s)\n", pubkey_str);

    sprintf(query_buf, "INSERT IGNORE INTO blk_contents VALUES(%d, %lu, %lu, %lu, '%s', %u , '%s', '%s', '%s', %lu)", 
                        subnet_id, p_light_blk->blk_num, p_light_blk->p2p_addr, p_light_blk->bgt, prv_hash_str, 
                        p_light_blk->tx_cnt, hash_str, sig_str, pubkey_str, (uint64_t)0);
    DBG_PRINT(DBG_DB, DBG_NONE, (void *) "%s", query_buf);
    
    if(mysql_query(&p_mysql_inst->conn_db, query_buf))
    {
        mysql_print_error(query_buf, mysql_error(&p_mysql_inst->conn_db));

        return (DB_RESULT_FAILURE);
    }

    get_current_rss_monitor(DBG_NONE, (char *)"2");

    return (DB_RESULT_SUCCESS);
}

// Update Table - block DB
DB_RESULT_E mysql_update_bct_t_blk_contents_w_bn(uint64_t blk_num, uint64_t bct)
{
    DB_RESULT_E db_ret = DB_RESULT_FAILURE;
    
    MYSQL_INST_T *p_mysql_inst = (MYSQL_INST_T *)db_get_db_inst_mgr();
    char query_buf[QUERY_MAX_SIZE];

    DBG_PRINT(DBG_DB, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    get_current_rss_monitor(DBG_NONE, (char *)"1");
    
    sprintf(query_buf, "UPDATE blk_contents SET bct = %lu WHERE blk_num = %lu", bct, blk_num);
    DBG_PRINT(DBG_DB, DBG_NONE, (void *)"query_buf (%s)\n", query_buf);
    DBG_PRINT(DBG_DB, DBG_NONE, (void *) "blk_num (0x%016llX)\n", blk_num);

    do
    {
        if(mysql_query(&p_mysql_inst->conn_db, query_buf))
        {
            mysql_print_error(query_buf, mysql_error(&p_mysql_inst->conn_db));
            
            db_ret = DB_RESULT_FAILURE;
            break;
        }
    } while(0);

    get_current_rss_monitor(DBG_NONE, (char *)"2");
    
    return (db_ret);
}

DB_RESULT_E mysql_update_bn_t_blk_txs_w_bn0(uint64_t blk_num)
{
    DB_RESULT_E db_ret = DB_RESULT_FAILURE;
    
    MYSQL_INST_T *p_mysql_inst = (MYSQL_INST_T *)db_get_db_inst_mgr();
    char query_buf[QUERY_MAX_SIZE];

    P2P_CNTX_T *p_p2p_cntx = p2p_get_cntx();
    uint16_t subnet_id;

    DBG_PRINT(DBG_DB, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    get_current_rss_monitor(DBG_NONE, (char *)"1");

    subnet_id = p_p2p_cntx->my_uniq_addr;
    
    sprintf(query_buf, "UPDATE blk_txs SET blk_num = %lu WHERE subnet_id = %d AND blk_num = %lu", blk_num, subnet_id, uint64_t(0));
    DBG_PRINT(DBG_DB, DBG_NONE, (void *)"query_buf (%s)\n", query_buf);
    DBG_PRINT(DBG_DB, DBG_NONE, (void *) "blk_num (0x%016llX)\n", blk_num);

    do
    {
        if(mysql_query(&p_mysql_inst->conn_db, query_buf))
        {
            mysql_print_error(query_buf, mysql_error(&p_mysql_inst->conn_db));
            
            db_ret = DB_RESULT_FAILURE;
            break;
        }
    } while(0);

    get_current_rss_monitor(DBG_NONE, (char *)"2");
    
    return (db_ret);
}



// Select Table - block DB
DB_RESULT_E mysql_select_xor_txs_f_blk_txs_w_bn(DB_TX_FIELD_T *p_db_tx)
{
    MYSQL_RES *res_tx;
    
    MYSQL_INST_T *p_mysql_inst = (MYSQL_INST_T *)db_get_db_inst_mgr();

    char tx_db_str[DB_PATH_STR_LEN];

    DBG_PRINT(DBG_DB, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    get_current_rss_monitor(DBG_NONE, (char *)"1");

    // Init as All ZERO
    MEMSET_M(&p_db_tx->db_key, 0x0, DB_KEY_SIZE);
    MEMSET_M(p_db_tx->sc_hash, 0x0, HASH_SIZE);

    // Size of hashing to block data.
    sprintf(tx_db_str, "SELECT db_key, sc_hash FROM blk_txs WHERE blk_num = %lu", p_db_tx->blk_num);
    DBG_PRINT(DBG_DB, DBG_NONE, (void *)"tx_db_str (%s)\n",tx_db_str);
    DBG_PRINT(DBG_DB, DBG_NONE, (void *) "blk_num (0x%016llX)\n", p_db_tx->blk_num);

    if( mysql_query(&p_mysql_inst->conn_db, tx_db_str))
    {
        mysql_print_error(tx_db_str, mysql_error(&p_mysql_inst->conn_db));

        return (DB_RESULT_FAILURE);
    }

    res_tx = mysql_store_result(&p_mysql_inst->conn_db);
    if(res_tx == NULL)
    {
        DBG_PRINT(DBG_DB, DBG_ERROR, (void *)"(query fail) mysql_query_error \n");
        return (DB_RESULT_FAILURE);
    }

    do
    {
        MYSQL_ROW row;
        int32_t field_num;

        field_num = mysql_num_fields(res_tx);
        ASSERT_M(field_num == 2); // db_key & sc_hash

        row = mysql_fetch_row(res_tx);

        if(row)
        {
            DB_TX_FIELD_T tmp_db_tx;
            
            p_db_tx->db_key = ATOI_M(row[0]);
            util_str2hex_temp(row[1], (unsigned char *)&p_db_tx->sc_hash, HASH_SIZE, false);
            
            row = mysql_fetch_row(res_tx);

            while(row)
            {
                tmp_db_tx.db_key = ATOI_M(row[0]);
                xor_m(&p_db_tx->db_key, &p_db_tx->db_key, &tmp_db_tx.db_key, DB_KEY_SIZE);
                
                util_str2hex_temp(row[1], (unsigned char *)&tmp_db_tx.sc_hash, HASH_SIZE, false);
                DBG_DUMP(DBG_DB, DBG_NONE, (void *)"(before)res_db_tx", (unsigned char *)&p_db_tx->sc_hash, HASH_SIZE);
                DBG_DUMP(DBG_DB, DBG_NONE, (void *)"tmp_db_tx", (unsigned char *)&tmp_db_tx.sc_hash, HASH_SIZE);
                xor_m(&p_db_tx->sc_hash, &p_db_tx->sc_hash, &tmp_db_tx.sc_hash, HASH_SIZE);
                DBG_DUMP(DBG_DB, DBG_NONE, (void *)"(after)res_db_tx", (unsigned char *)&p_db_tx->sc_hash, HASH_SIZE);
                
                row = mysql_fetch_row(res_tx);
            }
        }

    } while(0);

    mysql_free_result(res_tx);

    get_current_rss_monitor(DBG_NONE, (char *)"2");

    return (DB_RESULT_SUCCESS);
}

uint32_t mysql_select_count_f_blk_txs_w_bn(uint64_t blk_num)
{
    MYSQL_RES *res;     //res_hash,
    MYSQL_ROW row;

    MYSQL_INST_T *p_mysql_inst = (MYSQL_INST_T *)db_get_db_inst_mgr();
    char query_buf[QUERY_MAX_SIZE];

    uint32_t total_tx = 0;

    DBG_PRINT(DBG_DB, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    get_current_rss_monitor(DBG_NONE, (char *)"1");

    sprintf(query_buf, "SELECT COUNT(*) FROM blk_txs WHERE blk_num = %lu", blk_num);
    DBG_PRINT(DBG_DB, DBG_NONE, (void *)"query_buf (%s)\n",query_buf);
    DBG_PRINT(DBG_DB, DBG_NONE, (void *) "blk_num (0x%016llX)\n", blk_num);

    if( mysql_query(&p_mysql_inst->conn_db, query_buf) )
    {
        DBG_PRINT(DBG_DB, DBG_ERROR, (void *)"(%s) mysql_query_error \n", query_buf);
        return ERROR_;
    }

    res = mysql_store_result(&p_mysql_inst->conn_db);
    if(res == NULL)
    {
        DBG_PRINT(DBG_DB, DBG_ERROR, (void *)"(query fail) mysql_query_error \n");
        return (ERROR_);
    }
   
    if(mysql_num_rows(res) == 1)
    {
        row = mysql_fetch_row(res);
        total_tx = ATOI_M(row[0]);
    }
    else if(mysql_num_rows(res) == 0)
    {
        total_tx = 0;
    }
    else
    {
        // error 
        DBG_PRINT(DBG_DB, DBG_ERROR, (void *)"same number block exists.\n");
        mysql_free_result(res);
        
        return (ERROR_);
    }

    DBG_PRINT(DBG_DB, DBG_NONE, (void *)"blk_num(0x%016llX), total_tx_count(%u)\n",blk_num, total_tx);

    mysql_free_result(res);

    get_current_rss_monitor(DBG_NONE, (char *)"2");

    return (total_tx);
}

DB_RESULT_E mysql_select_hash_f_blk_txs_w_dk(uint64_t db_key, uint8_t *p_tx_hash)
{
    MYSQL_RES *res;
    MYSQL_ROW row;

    MYSQL_INST_T *p_mysql_inst = (MYSQL_INST_T *)db_get_db_inst_mgr();
    char query_buf[QUERY_MAX_SIZE];

    DBG_PRINT(DBG_DB, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    get_current_rss_monitor(DBG_NONE, (char *)"1");
    
    sprintf(query_buf, "SELECT sc_hash FROM blk_txs WHERE db_key = %lu", db_key);
    DBG_PRINT(DBG_DB, DBG_NONE, (void *)"query_buf (%s)\n", query_buf);
    DBG_PRINT(DBG_DB, DBG_NONE, (void *) "db_key (0x%016llX)\n", db_key);

    if(mysql_query(&p_mysql_inst->conn_db, query_buf))
    {
        DBG_PRINT(DBG_DB, DBG_ERROR, (void *)"(%s) mysql_query_error \n", query_buf);
        return (DB_RESULT_FAILURE);
    }

    res = mysql_store_result(&p_mysql_inst->conn_db);
    if(res == NULL)
    {
        DBG_PRINT(DBG_DB, DBG_ERROR, (void *)"(query fail) mysql_query_error \n");
        return (DB_RESULT_FAILURE);
    }

    do
    {
        uint32_t cnt;

        cnt = mysql_num_rows(res);
        if(cnt == 1)
        {
            row = mysql_fetch_row(res);

            DBG_PRINT(DBG_DB, DBG_INFO, (void *)"(sc_hash) value : (%s)\n", row[0]);
            util_str2hex_temp(row[0], p_tx_hash, HASH_SIZE, false);
        }
        else
        {
            DBG_PRINT(DBG_DB, DBG_ERROR, (void *)"Error : ROW Count(%d) , Count should be equal to ONE.\n", cnt);
            ASSERT_M(0);
        }
    } while(0);

    mysql_free_result(res);

    get_current_rss_monitor(DBG_NONE, (char *)"2");
    
    return (DB_RESULT_SUCCESS);
}

uint64_t mysql_select_db_key_f_blk_txs_w_bn(uint64_t blk_num, bool min_v)
{
    MYSQL_INST_T *p_mysql_inst = (MYSQL_INST_T *)db_get_db_inst_mgr();
    char query_buf[QUERY_MAX_SIZE];
    
    uint64_t db_key = 0;

    DBG_PRINT(DBG_DB, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    get_current_rss_monitor(DBG_NONE, (char *)"1");

    if (min_v == true) // MIN
    {
        sprintf(query_buf, "SELECT MIN(db_key) FROM blk_txs WHERE blk_num = %lu", blk_num);
    }
    else // MAX
    {
        sprintf(query_buf, "SELECT MAX(db_key) FROM blk_txs WHERE blk_num = %lu", blk_num);
    }
    
    DBG_PRINT(DBG_DB, DBG_NONE, (void *)"query_buf (%s)\n", query_buf);
    DBG_PRINT(DBG_DB, DBG_NONE, (void *) "blk_num (0x%016llX)\n", blk_num);

    do
    {
        MYSQL_RES *res;
        MYSQL_ROW row;

        if( mysql_query(&p_mysql_inst->conn_db, query_buf) )
        {
            DBG_PRINT(DBG_DB, DBG_ERROR, (void *)"(%s) mysql_query_error \n", query_buf);
            break;
        }

        res = mysql_store_result(&p_mysql_inst->conn_db);
        if(res == NULL)
        {
            DBG_PRINT(DBG_DB, DBG_ERROR, (void *)"(query fail) mysql_query_error \n");
            break;
        }

        do
        {
            if(mysql_num_rows(res) == 1)
            {
                row = mysql_fetch_row(res);
                if(row[0] != NULL)
                {
                    db_key = ATOI_64_M(row[0]);
                }
            }
            else // maybe zero
            {
                DBG_PRINT(DBG_DB, DBG_ERROR, (void *)"DB.TX is empty\n");
                break;
            }
            
            DBG_PRINT(DBG_DB, DBG_NONE, (void *)"min(%d), db_key(0x%016llX)\n", min_v, db_key);
        } while(0);

        mysql_free_result(res);
    } while(0);

    get_current_rss_monitor(DBG_NONE, (char *)"2");
    
    return (db_key);
}

DB_RESULT_E mysql_select_blk_f_blk_contents_w_bn(uint64_t blk_num, CONS_LIGHT_BLK_T *p_light_blk)
{
    DB_RESULT_E db_ret = DB_RESULT_FAILURE;
    MYSQL_RES *res;
    MYSQL_ROW row;

    MYSQL_INST_T *p_mysql_inst = (MYSQL_INST_T *)db_get_db_inst_mgr();
    char query_buf[QUERY_MAX_SIZE];

    DBG_PRINT(DBG_DB, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    get_current_rss_monitor(DBG_NONE, (char *)"1");
    
    sprintf(query_buf, "SELECT * FROM blk_contents WHERE blk_num = %lu", blk_num);
    DBG_PRINT(DBG_DB, DBG_NONE, (void *)"query_buf (%s)\n", query_buf);
    DBG_PRINT(DBG_DB, DBG_NONE, (void *) "blk_num (0x%016llX)\n", blk_num);

    if(mysql_query(&p_mysql_inst->conn_db, query_buf))
    {
        DBG_PRINT(DBG_DB, DBG_ERROR, (void *)"(%s) mysql_query_error \n", query_buf);
        return (db_ret);
    }

    res = mysql_store_result(&p_mysql_inst->conn_db);
    if(res == NULL)
    {
        DBG_PRINT(DBG_DB, DBG_ERROR, (void *)"(query fail) mysql_query_error \n");
        return (db_ret);
    }
    
    do
    {
        int32_t field_num;
        uint32_t cnt;

        field_num = mysql_num_fields(res);
        cnt = mysql_num_rows(res);

        DBG_PRINT(DBG_DB, DBG_INFO, (void *)"field_num (%d) cnt(%d) \n", field_num, cnt);

        if(cnt == 1)
        {
            ASSERT_M (field_num == DB_BLK_CONTENTS_FIELD_NUM);
            
            row = mysql_fetch_row(res);

            p_light_blk->blk_num = ATOI_64_M(row[DB_IDX_BLK_NUM]);
            p_light_blk->p2p_addr = ATOI_64_M(row[DB_IDX_P2P_ADDR]);
            p_light_blk->bgt = ATOI_64_M(row[DB_IDX_BGT]);
            util_str2hex_temp(row[DB_IDX_PBH], (unsigned char *)p_light_blk->pbh, HASH_SIZE, false);
            p_light_blk->tx_cnt = ATOI_M(row[DB_IDX_TX_CNT]);
            util_str2hex_temp(row[DB_IDX_BLK_HASH], (unsigned char *)p_light_blk->blk_hash, HASH_SIZE, false);
            util_str2hex_temp(row[DB_IDX_SIG], (unsigned char *)p_light_blk->sig, SIG_SIZE, false);
            util_str2hex_temp(row[DB_IDX_SIG_PUBKEY], (unsigned char *)p_light_blk->sig_pubkey, COMP_PUBKEY_SIZE, false);

            DBG_PRINT(DBG_DB, DBG_INFO, (void *)"blk_num(0x%016llX) p2p_addr(0x%016llX) blk_gen_time(0x%016llX)\n", 
                                        p_light_blk->blk_num, p_light_blk->p2p_addr, p_light_blk->bgt);

            db_ret = DB_RESULT_SUCCESS;
        }
        else
        {
            // error
            ASSERT_M(0);
            break;
        }
    } while(0);

    mysql_free_result(res);

    get_current_rss_monitor(DBG_NONE, (char *)"2");
    
    return (db_ret);
}

DB_RESULT_E mysql_select_hash_f_blk_contents_w_bn(uint64_t blk_num, uint8_t *p_blk_hash)
{
    DB_RESULT_E db_ret = DB_RESULT_FAILURE;
    MYSQL_RES *res;
    MYSQL_ROW row;

    MYSQL_INST_T *p_mysql_inst = (MYSQL_INST_T *)db_get_db_inst_mgr();
    char query_buf[QUERY_MAX_SIZE];

    DBG_PRINT(DBG_DB, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    get_current_rss_monitor(DBG_NONE, (char *)"1");
    
    sprintf(query_buf, "SELECT blk_hash FROM blk_contents WHERE blk_num = %lu", blk_num);
    DBG_PRINT(DBG_DB, DBG_NONE, (void *)"query_buf (%s)\n", query_buf);
    DBG_PRINT(DBG_DB, DBG_NONE, (void *) "blk_num (0x%016llX)\n", blk_num);

    if(mysql_query(&p_mysql_inst->conn_db, query_buf))
    {
        DBG_PRINT(DBG_DB, DBG_ERROR, (void *)"(%s) mysql_query_error \n", query_buf);
        return (db_ret);
    }

    res = mysql_store_result(&p_mysql_inst->conn_db);
    if(res == NULL)
    {
        DBG_PRINT(DBG_DB, DBG_ERROR, (void *)"(query fail) mysql_query_error \n");
        return (db_ret);
    }

    do
    {
        uint32_t cnt;

        cnt = mysql_num_rows(res);

        if(cnt == 1)
        {
            int32_t len;
            
            row = mysql_fetch_row(res);
            
            len = HASH_SIZE;
            DBG_PRINT(DBG_DB, DBG_NONE, (void *)"(blk_hash) value : (%s)\n", row[0]);
            util_str2hex(row[0], (unsigned char *)p_blk_hash, &len);

            db_ret = DB_RESULT_SUCCESS;
        }
        else
        {
            // error
            ASSERT_M(0);
            break;
        }
    } while(0);

    mysql_free_result(res);

    get_current_rss_monitor(DBG_NONE, (char *)"2");
    
    return (db_ret);
}

uint64_t mysql_select_last_bn_f_blk_contents(void)
{
    MYSQL_RES *res;
    MYSQL_ROW row;

    MYSQL_INST_T *p_mysql_inst = (MYSQL_INST_T *)db_get_db_inst_mgr();
    char query_buf[QUERY_MAX_SIZE];
    
    uint64_t blk_num = 0;

    DBG_PRINT(DBG_DB, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    get_current_rss_monitor(DBG_NONE, (char *)"1");

    // select count(*) from TX where BLOCK_NUM = %lu. It's faster. but it's not used.
    
    sprintf(query_buf, "SELECT MAX(blk_num) FROM blk_contents");
    DBG_PRINT(DBG_DB, DBG_NONE, (void *)"query_buf (%s)\n", query_buf);
    
    if( mysql_query(&p_mysql_inst->conn_db, query_buf) )
    {
        DBG_PRINT(DBG_DB, DBG_ERROR, (void *)"(%s) mysql_query_error \n", query_buf);
        return (blk_num);
    }

    res = mysql_store_result(&p_mysql_inst->conn_db);
    if(res == NULL)
    {
        DBG_PRINT(DBG_DB, DBG_ERROR, (void *)"(query fail) mysql_query_error \n");
        return (blk_num);
    }

    do
    {
        if(mysql_num_rows(res) == 1)
        {
            row = mysql_fetch_row(res);
            if(row[0] != NULL)
            {
                blk_num = ATOI_64_M(row[0]);
            }
        }
        else // maybe zero
        {
            DBG_PRINT(DBG_DB, DBG_ERROR, (void *)"DB.BLOCK is empty\n");
        }

        DBG_PRINT(DBG_DB, DBG_INFO, (void *)"last_blk_num(0x%016llX)\n", blk_num);
    } while(0);
    
    mysql_free_result(res);

    get_current_rss_monitor(DBG_NONE, (char *)"2");

    return (blk_num);
}

uint64_t mysql_select_bct_f_blk_contents_w_bn(uint64_t blk_num)
{
    MYSQL_INST_T *p_mysql_inst = (MYSQL_INST_T *)db_get_db_inst_mgr();
    char query_buf[QUERY_MAX_SIZE];

    uint64_t bct = 0;

    DBG_PRINT(DBG_DB, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    get_current_rss_monitor(DBG_NONE, (char *)"1");
    
    sprintf(query_buf, "SELECT bct FROM blk_contents WHERE blk_num = %lu", blk_num);
    DBG_PRINT(DBG_DB, DBG_NONE, (void *)"query_buf (%s)\n", query_buf);
    DBG_PRINT(DBG_DB, DBG_NONE, (void *) "blk_num (0x%016llX)\n", blk_num);

    do
    {
        MYSQL_RES *res;
        MYSQL_ROW row;

        if(mysql_query(&p_mysql_inst->conn_db, query_buf))
        {
            DBG_PRINT(DBG_DB, DBG_ERROR, (void *)"(%s) mysql_query_error \n", query_buf);
            break;
        }
        
        res = mysql_store_result(&p_mysql_inst->conn_db);
        if(res == NULL)
        {
            DBG_PRINT(DBG_DB, DBG_ERROR, (void *)"(query fail) mysql_query_error \n");
            break;
        }

        do
        {
            if(mysql_num_rows(res) == 1)
            {
                row = mysql_fetch_row(res);
                if(row[0] != NULL)
                {
                    bct = ATOI_64_M(row[0]);
                }
            }
            else // maybe zero
            {
                DBG_PRINT(DBG_DB, DBG_ERROR, (void *)"DB.BLK_CONTENTS is empty\n");
                break;
            }
            
            DBG_PRINT(DBG_DB, DBG_NONE, (void *)"bct(0x%016llX)\n", bct);
        } while(0);


        mysql_free_result(res);
    } while(0);

    get_current_rss_monitor(DBG_NONE, (char *)"2");
    
    return (bct);
}


