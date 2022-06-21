/**
    @file db_interface.h
    @date 2019/02/12
    @author FINL Chain Team
    @version 
    @brief 
*/

#ifndef   __DB_INTEFACE_H__
#define   __DB_INTEFACE_H__

#ifdef __cplusplus
extern "C"
{
#endif

//
typedef struct {
	DB_TYPE_E                db_type;

	int32_t                  b_use_ssl;

	void                    *p_mgr;    /** mongo: (mongoc_client *), mysql: (MYSQL *)     **/
	uint16_t                 mgr_cnt; /** TODO:  db instance size scailing function      **/
} DB_INSTANCE_T;

//
extern DB_INSTANCE_T *db_inst_create(DB_TYPE_E db_type);
extern void db_inst_destroy_sub(DB_INSTANCE_T **p_db_inst);
extern void db_inst_destroy(void);

//
extern DB_RESULT_E  db_set_conn_info(DB_INSTANCE_T *p_db_inst, char *p_db_host, uint16_t db_port, char *p_db_user, char *p_db_pw, char *p_db_name, char *p_db_sock, char *p_pw_path, char *p_seed_path);

#ifdef __cplusplus
} // EOF: extern "c"
#endif

#endif // __DB_INTEFACE_H__

// EOF; db_interface.h
