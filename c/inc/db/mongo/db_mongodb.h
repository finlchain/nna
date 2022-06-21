/**
    @file db_mongodb.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#ifndef  __DB_MONGODB_H__
#define  __DB_MONGODB_H__

#ifdef __cplusplus
extern "C"
{
#endif

#define MONGODB_DESCENDING_ORDER    -1  //
#define MONGODB_ASCENDING_ORDER     1   //

#define MONGODB_IDX_NAME_STR_SIZE   50

#define DB_SUBNET_ID_STR "subnet_id"
#define DB_SUBNET_ID_STR_SIZE STRLEN_M(DB_SUBNET_ID_STR)

#define DB_BLK_NUM_STR "blk_num"
#define DB_BLK_NUM_STR_SIZE STRLEN_M(DB_BLK_NUM_STR)

#define DB_DB_KEY_STR "db_key"
#define DB_DB_KEY_STR_SIZE STRLEN_M(DB_DB_KEY_STR)

#define DB_SC_HASH_STR "sc_hash"
#define DB_SC_HASH_STR_SIZE STRLEN_M(DB_SC_HASH_STR)

#define DB_STATUS_STR "status"
#define DB_STATUS_STR_SIZE STRLEN_M(DB_STATUS_STR)

#define DB_BCT_STR "bct"
#define DB_BCT_STR_SIZE STRLEN_M(DB_BCT_STR)

#define DB_SIG_STR "sig"
#define DB_SIG_STR_SIZE STRLEN_M(DB_SIG_STR)

#define DB_P2P_ADDR_STR "p2p_addr"
#define DB_P2P_ADDR_STR_SIZE STRLEN_M(DB_P2P_ADDR_STR)

#define DB_BGT_STR "bgt"
#define DB_BGT_STR_SIZE STRLEN_M(DB_BGT_STR)

#define DB_PBH_STR "pbt"
#define DB_PBH_STR_SIZE STRLEN_M(DB_PBH_STR)

#define DB_TX_CNT_STR "tx_cnt"
#define DB_TX_CNT_STR_SIZE STRLEN_M(DB_TX_CNT_STR)

#define DB_BLK_HASH_STR "blk_hash"
#define DB_BLK_HASH_STR_SIZE STRLEN_M(DB_BLK_HASH_STR)

#define DB_SIG_PUBKEY_STR "sig_pubkey"
#define DB_SIG_PUBKEY_STR_SIZE STRLEN_M(DB_SIG_PUBKEY_STR)

typedef struct MONGODB_INST_ST{
	mongoc_client_t         *p_client;
	mongoc_database_t       *p_db;
	mongoc_collection_t     *p_blk_txs;
	mongoc_collection_t     *p_blk_info;
    mongoc_collection_t     *p_blk_contents;
    mongoc_collection_t     *p_blk_prv_contents;

	struct timeval          queryBegin;
	struct timeval          queryEnd;

	mongoc_bulk_operation_t *p_bulk;
} MONGODB_INST_T;

typedef struct stcMongoInstManager {
    MONGODB_INST_T     *p_inst;
	int                inst_cnt;

	pthread_mutex_t    inst_get_mtx;
	pthread_cond_t     inst_get_cond;
} MONGODB_INST_MGR_T;

//
extern void mongodb_get_svr_version(void);
extern void mongodb_get_cli_version(void);

//
extern DB_RESULT_E  mongodb_conn_init(void **pp_mgr, uint16_t mgr_cnt, char *p_db_host, uint16_t db_port, char *p_db_user, char *p_db_pw, char *p_db_name, char *p_db_sock);
extern void mongodb_conn_close(void **pp_mgr);
extern DB_RESULT_E mongodb_truncate(void);

// Insert Table - block DB
extern DB_RESULT_E mongodb_insert_t_blk_tx(uint64_t blk_num, uint64_t db_key, uint8_t *p_sc_hash);
// bulk insertion, mongodb_insert_t_blk_tx_start() return db instance. other function arg == db_inst
extern void *mongodb_insert_t_blk_tx_start(uint32_t len);
extern DB_RESULT_E mongodb_insert_t_blk_tx_process(void *p_arg, bool b_last, uint64_t blk_num, uint64_t db_key, uint8_t *p_sc_hash);
extern DB_RESULT_E mongodb_insert_t_blk_tx_end(void *p_arg);
extern DB_RESULT_E mongodb_insert_t_blk_contents(CONS_LIGHT_BLK_T *p_light_blk);

// Update Table - block DB
extern DB_RESULT_E mongodb_update_bn_t_blk_txs_w_dk(uint64_t db_key, uint64_t blk_num);
extern DB_RESULT_E mongodb_update_status_t_blk_info_w_bn(uint64_t blk_num, uint64_t status, uint64_t blk_cfm_time);

// Select Table - block DB
extern DB_RESULT_E mongodb_select_xor_txs_f_blk_txs_w_bn(DB_TX_FIELD_T *p_db_tx);
extern uint32_t mongodb_select_count_f_blk_txs_w_bn(uint64_t blk_num);
extern DB_RESULT_E mongodb_select_hash_f_blk_txs_w_dk(uint64_t db_key, uint8_t *p_tx_hash);
extern uint64_t mongodb_select_db_key_f_blk_txs_w_bn(uint64_t blk_num, bool min_v);
extern DB_RESULT_E mongodb_select_blk_f_blk_contents_w_bn(uint64_t blk_num, CONS_LIGHT_BLK_T *p_light_blk);
extern DB_RESULT_E mongodb_select_blk_f_blk_prv_contents_w_bn(uint64_t blk_num, CONS_LIGHT_BLK_T *p_light_blk);
extern DB_RESULT_E mongodb_select_hash_f_blk_contents_w_bn(uint64_t blk_num, uint8_t *p_blk_hash);
extern DB_RESULT_E mongodb_select_hash_f_blk_prv_contents_w_bn(uint64_t blk_num, uint8_t *p_blk_hash);
extern uint64_t mongodb_select_last_bn_f_blk_contents(void);

#ifdef __cplusplus
}
#endif

#endif // __DB_MONGODB_H__

// EOF: db_mongodb.h
