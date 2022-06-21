/**
    @file db_config.h
    @date 2019/02/12
    @author FINL Chain Team
    @version 
    @brief 
*/

#ifndef __DB_CONFIG_H__
#define __DB_CONFIG_H__

#ifdef __cplusplus
extern "C"
{
#endif

#if defined(USE_MYSQL)
// 
#define DB_GET_SVR_VERSION mysql_get_svr_version
#define DB_GET_CLI_VERSION mysql_get_cli_version

//
#define DB_CONN_INIT mysql_conn_init
#define DB_CONN_CLOSE mysql_conn_close
#define DB_TRUNCATE mysql_truncate

// Insert Table - block DB
#define DB_INSERT_T_BLK_TX mysql_insert_t_blk_tx
#define DB_INSERT_T_BLK_TX_START mysql_insert_t_blk_tx_start
#define DB_INSERT_T_BLK_TX_PROCESS mysql_insert_t_blk_tx_process
#define DB_INSERT_T_BLK_TX_END mysql_insert_t_blk_tx_end
#define DB_INSERT_T_BLK_CONTENTS mysql_insert_t_blk_contents

// Update Table - block DB
#define DB_UPDATE_BCT_T_BLK_CONTENTS_W_BN mysql_update_bct_t_blk_contents_w_bn
#define DB_UPDATE_BN_T_BLK_TXS_W_BN0 mysql_update_bn_t_blk_txs_w_bn0
#define DB_UPDATE_BN_T_BLK_TXS_W_DK 
#define DB_UPDATE_STATUS_T_BLK_INFO_W_BN 

// Select Table - block DB
#define DB_SELECT_XOR_TXS_F_BLK_TXS_W_BN mysql_select_xor_txs_f_blk_txs_w_bn
#define DB_SELECT_COUNT_F_BLK_TXS_W_BN mysql_select_count_f_blk_txs_w_bn
#define DB_SELECT_HASH_F_BLK_TXS_W_DK mysql_select_hash_f_blk_txs_w_dk
#define DB_SELECT_DB_KEY_F_BLK_TXS_W_BN mysql_select_db_key_f_blk_txs_w_bn
#define DB_SELECT_1ST_DB_KEY_F_BLK_TXS_W_BN(BN) mysql_select_db_key_f_blk_txs_w_bn(BN, true)
#define DB_SELECT_LAST_DB_KEY_F_BLK_TXS_W_BN(BN) mysql_select_db_key_f_blk_txs_w_bn(BN, false)
#define DB_SELECT_BLK_F_BLK_CONTENTS_W_BN mysql_select_blk_f_blk_contents_w_bn
#define DB_SELECT_HASH_F_BLK_CONTENTS_W_BN mysql_select_hash_f_blk_contents_w_bn
#define DB_SELECT_LAST_BN_F_BLK_CONTENTS mysql_select_last_bn_f_blk_contents
#define DB_SELECT_BCT_F_BLK_CONTENTS_W_BN mysql_select_bct_f_blk_contents_w_bn

#elif defined(USE_MONGODB) // if mongo
//
#define DB_GET_SVR_VERSION mongodb_get_svr_version
#define DB_GET_CLI_VERSION mongodb_get_cli_version

//
#define DB_CONN_INIT mongodb_conn_init
#define DB_CONN_CLOSE mongodb_conn_close
#define DB_TRUNCATE mongodb_truncate

// Insert Table - block DB
#define DB_INSERT_T_BLK_TX mongodb_insert_t_blk_tx
#define DB_INSERT_T_BLK_TX_START mongodb_insert_t_blk_tx_start
#define DB_INSERT_T_BLK_TX_PROCESS mongodb_insert_t_blk_tx_process
#define DB_INSERT_T_BLK_TX_END mongodb_insert_t_blk_tx_end
#define DB_INSERT_T_BLK_CONTENTS mongodb_insert_t_blk_contents

// Update Table - block DB
#define DB_UPDATE_BCT_T_BLK_CONTENTS_W_BN 
#define DB_UPDATE_BN_T_BLK_TXS_W_BN0 
#define DB_UPDATE_BN_T_BLK_TXS_W_DK mongodb_update_bn_t_blk_txs_w_dk
#define DB_UPDATE_STATUS_T_BLK_INFO_W_BN mongodb_update_status_t_blk_info_w_bn

// Select Table - block DB
#define DB_SELECT_XOR_TXS_F_BLK_TXS_W_BN mongodb_select_xor_txs_f_blk_txs_w_bn
#define DB_SELECT_COUNT_F_BLK_TXS_W_BN mongodb_select_count_f_blk_txs_w_bn
#define DB_SELECT_HASH_F_BLK_TXS_W_DK mongodb_select_hash_f_blk_txs_w_dk
#define DB_SELECT_DB_KEY_F_BLK_TXS_W_BN mongodb_select_db_key_f_blk_txs_w_bn
#define DB_SELECT_1ST_DB_KEY_F_BLK_TXS_W_BN(BN) mongodb_select_db_key_f_blk_txs_w_bn(BN, true)
#define DB_SELECT_LAST_DB_KEY_F_BLK_TXS_W_BN(BN) mongodb_select_db_key_f_blk_txs_w_bn(BN, false)
#define DB_SELECT_BLK_F_BLK_CONTENTS_W_BN mongodb_select_blk_f_blk_contents_w_bn
#define DB_SELECT_HASH_F_BLK_CONTENTS_W_BN mongodb_select_hash_f_blk_contents_w_bn
#define DB_SELECT_LAST_BN_F_BLK_CONTENTS mongodb_select_last_bn_f_blk_contents
#define DB_SELECT_BCT_F_BLK_CONTENTS_W_BN 
#endif

#define DB_BLK_CONTENTS_FIELD_NUM   9
#define DB_IDX_SUBNET_ID            0
#define DB_IDX_BLK_NUM              1
#define DB_IDX_P2P_ADDR             2
#define DB_IDX_BGT                  3
#define DB_IDX_PBH                  4
#define DB_IDX_TX_CNT               5
#define DB_IDX_BLK_HASH             6
#define DB_IDX_SIG                  7
#define DB_IDX_SIG_PUBKEY           8

typedef struct
{
    uint64_t blk_num;
    uint64_t db_key;
    uint8_t sc_hash[HASH_SIZE];
} __attribute__((__packed__)) DB_TX_FIELD_T;

#ifdef __cplusplus
}
#endif

#endif /* __DB_CONFIG_H__ */

