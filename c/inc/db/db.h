/**
    @file db.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#ifndef __DB_H__
#define __DB_H__

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct 
{
    uint32_t tx_cnt;
    LIST_T tx_list;
} DB_TX_INFO_T;


typedef struct 
{
    DB_PW_INFO_T    pw_info;
    DB_CONN_INFO_T  conn_info;
    DB_TX_INFO_T    tx_info;
    //
    DB_INSTANCE_T   *p_db_inst;
} DB_CNTX_T;

typedef struct
{
    LIST_ITEM_T link;
    DB_TX_FIELD_T tx_field;
} __attribute__((__packed__)) DB_TX_LIST_T;

#if (CONS_TO_DB_TASK == ENABLED)
//
extern void db_tx_list_add(DB_TX_FIELD_T *p_tx_field);
extern void db_tx_list_remove(void);
#endif // CONS_TO_DB_TASK

//
extern DB_CNTX_T *db_get_cntx(void);
extern DB_PW_INFO_T *db_get_pw_info(void);
extern DB_CONN_INFO_T *db_get_conn_info(void);
extern DB_TX_INFO_T *db_get_tx_info(void);
extern void *db_get_db_inst_mgr(void);

//
extern void db_task_init(void);
extern void *t_db_main(void *p_data);

#ifdef __cplusplus
}
#endif

#endif /* __DB_H__ */

