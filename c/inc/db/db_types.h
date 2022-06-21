/**
    @file db_types.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#ifndef   __DB_TYPES_H__
#define   __DB_TYPES_H__

#ifdef __cplusplus
extern "C"
{
#endif


#define DB_CONN_INIT_ERR    0
#define DB_CONN_INIT_OK     1

#define DB_INST_DEFAULT_CONN_CNT    4

#define BLK_NOTI_STR_SIZE   (BLK_NUM_STR_DATA_SIZE + BGT_STR_DATA_SIZE + TX_CNT_STR_DATA_SIZE + HASH_STR_DATA_SIZE + 1)

#define QUERY_MAX_SIZE      1000
#define QUERY_TX_ITEM_SIZE  120

/** TODO: error message definition according to error type. **/
typedef enum {
    DB_RESULT_SUCCESS  = 0,
    DB_RESULT_CONN_FAILURE,
    DB_RESULT_WRONG_PARAM,
    DB_RESULT_INSTANCE_GET_FAILURE,
    DB_RESULT_FAILURE
} DB_RESULT_E;

typedef enum {
    DB_TYPE_MYSQL  = 0,
    DB_TYPE_MONGODB
} DB_TYPE_E;

#define  DB_CONN_STRING_LEN             128
typedef struct {
    int16_t      init;
    int16_t      db_port;
    DB_TYPE_E    db_type;
    char         db_host[DB_CONN_STRING_LEN];
    char         db_user[DB_CONN_STRING_LEN];
    char         db_pw[DB_CONN_STRING_LEN];
    char         db_name[DB_CONN_STRING_LEN];
    char         db_sock[DB_CONN_STRING_LEN];
    //
    char         db_pw_path[DB_CONN_STRING_LEN];
    char         db_seed_path[DB_CONN_STRING_LEN];
} DB_CONN_INFO_T;

#define  DB_PW_STRING_LEN             128
typedef struct {
    //
} DB_PW_INFO_T;


#ifdef __cplusplus
} // EOF: extern "c"
#endif


#endif // __DB_TYPES_H__

// EOF; db_types.h
