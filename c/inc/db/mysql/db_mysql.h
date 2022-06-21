/**
    @file db_mysql.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#ifndef __DB_MYSQL_H__
#define __DB_MYSQL_H__

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct {
	MYSQL conn;
    MYSQL conn_db; // block
} MYSQL_INST_T;

//
extern void mysql_get_svr_version(void);
extern void mysql_get_cli_version(void);

//
extern DB_RESULT_E mysql_conn_init(void **pp_mgr, uint16_t mgr_cnt, char *p_db_host, uint16_t db_port, char *p_db_user, char *p_db_pw, char *p_db_name, char *p_db_sock, char *p_pw_path, char *p_seed_path);
extern void mysql_conn_close(void **pp_mgr);
extern DB_RESULT_E mysql_truncate(void);

// Insert Table - block DB
extern DB_RESULT_E mysql_insert_t_blk_tx(uint64_t blk_num, uint64_t db_key, uint8_t *p_sc_hash);
extern void *mysql_insert_t_blk_tx_start(uint32_t len);
extern DB_RESULT_E mysql_insert_t_blk_tx_process(void *p_arg, bool b_last, uint64_t blk_num, uint64_t db_key, uint8_t *p_sc_hash);
extern DB_RESULT_E mysql_insert_t_blk_tx_end(void *p_arg);
extern DB_RESULT_E mysql_insert_t_blk_contents(CONS_LIGHT_BLK_T *p_light_blk);

// Update Table - block DB
extern DB_RESULT_E mysql_update_bct_t_blk_contents_w_bn(uint64_t blk_num, uint64_t bct);
extern DB_RESULT_E mysql_update_bn_t_blk_txs_w_bn0(uint64_t blk_num);

// Select - block DB
extern DB_RESULT_E mysql_select_xor_txs_f_blk_txs_w_bn(DB_TX_FIELD_T *p_db_tx);
extern uint32_t mysql_select_count_f_blk_txs_w_bn(uint64_t blk_num);
extern DB_RESULT_E mysql_select_hash_f_blk_txs_w_dk(uint64_t db_key, uint8_t *p_tx_hash);
extern uint64_t mysql_select_db_key_f_blk_txs_w_bn(uint64_t blk_num, bool min_v);
extern DB_RESULT_E mysql_select_blk_f_blk_contents_w_bn(uint64_t blk_num, CONS_LIGHT_BLK_T *p_light_blk);
extern DB_RESULT_E mysql_select_hash_f_blk_contents_w_bn(uint64_t blk_num, uint8_t *p_blk_hash);
extern uint64_t mysql_select_last_bn_f_blk_contents(void);
extern uint64_t mysql_select_bct_f_blk_contents_w_bn(uint64_t blk_num);

#ifdef __cplusplus
}
#endif

#endif /* __DB_MYSQL_H__ */

