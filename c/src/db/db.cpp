/**
    @file db.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

DB_CNTX_T     g_db_cntx;

#if (CONS_TO_DB_TASK == ENABLED)
static void db_tx_list_init(void) 
{
    DB_TX_INFO_T *p_tx_info = db_get_tx_info();
    
    p_tx_info->tx_cnt = 0;
    list_init(&p_tx_info->tx_list);
}

void db_tx_list_add(DB_TX_FIELD_T *p_tx_field) 
{
    DB_TX_INFO_T *p_tx_info = db_get_tx_info();
    DB_TX_LIST_T *p_tx_list;

    p_tx_list = (DB_TX_LIST_T *)MALLOC_M(sizeof(DB_TX_LIST_T));
    list_insert(&p_tx_info->tx_list, &p_tx_list->link);

    MEMCPY_M(&p_tx_list->tx_field, p_tx_field, sizeof(DB_TX_FIELD_T));
}

void db_tx_list_remove(void) 
{
    DB_TX_INFO_T *p_tx_info = db_get_tx_info();
    DB_TX_LIST_T *p_tx_list;
    DB_TX_FIELD_T *p_tx_field;

    if(list_is_empty(&p_tx_info->tx_list))
    {
        return;
    }

    do
    {
        bool b_last = false;
        
        uint32_t len;
        void *p_arg;

        len = QUERY_MAX_SIZE+(QUERY_TX_ITEM_SIZE * p_tx_info->tx_list.num_items);
        DBG_PRINT(DBG_DB, DBG_NONE, (void *)"tx_list : num_items(%d), total len(%d)\n", p_tx_info->tx_list.num_items, len);
        
        p_arg = DB_INSERT_T_BLK_TX_START(len);

        while (!list_is_empty(&p_tx_info->tx_list))
        {
            p_tx_list = (DB_TX_LIST_T *)list_remove(&p_tx_info->tx_list);

            p_tx_field = &p_tx_list->tx_field;

            if (!p_tx_info->tx_list.num_items)
            {
                b_last = true;
            }
            
            DB_INSERT_T_BLK_TX_PROCESS(p_arg, b_last, p_tx_field->blk_num, p_tx_field->db_key, p_tx_field->sc_hash);

            FREE_M(p_tx_list);
        }

        DB_INSERT_T_BLK_TX_END(p_arg);
    } while (0);
}
#endif // CONS_TO_DB_TASK

static void db_cntx_init(void)
{
    MEMSET_M(&g_db_cntx, 0x00, sizeof(DB_CNTX_T));

#if (CONS_TO_DB_TASK == ENABLED)
    db_tx_list_init();
#endif // CONS_TO_DB_TASK

    g_db_cntx.p_db_inst = NULL;
}

DB_CNTX_T *db_get_cntx(void)
{
    return (&g_db_cntx);
}

DB_PW_INFO_T *db_get_pw_info(void)
{
    return (&g_db_cntx.pw_info);
}

DB_CONN_INFO_T *db_get_conn_info(void)
{
    return (&g_db_cntx.conn_info);
}

DB_TX_INFO_T *db_get_tx_info(void)
{
    return (&g_db_cntx.tx_info);
}

void *db_get_db_inst_mgr(void)
{
    return (g_db_cntx.p_db_inst->p_mgr);
}


void *t_db_main(void *p_data)
{
    pid_t pid; // process id
    
    char* thread_name = (char*)p_data;
    bool exe_thread = true;
    int task_ret = TASK_EXIT_NORMAL;

#if (defined (_WIN32) || defined (_WIN64))
    pthread_t tid; // thread id
    
    pid = GetCurrentProcessId();
    tid = pthread_self();
#else
    pid_t tid;

    pid = getpid();
    tid = syscall(SYS_gettid);

    setpriority(PRIO_PROCESS, tid, g_tid_nice[DB_THREAD_IDX]);
#endif

    DBG_PRINT(DBG_CLI, DBG_TRACE, (void *)"%s\n", __FUNCTION__);
    DBG_PRINT(DBG_DB, DBG_INFO, (void *)"%s is started.! - pid(%d), tid(%d)\n", thread_name, pid, tid);

    db_timer_run();
    
    while (exe_thread)
    {
        db_task_msg_handler();

        usleep(10);
    }

	db_inst_destroy();

    pthread_exit(&task_ret);
    
    return (void *)p_data;
}

void db_task_init(void)
{
    db_task_msg_init();

    db_cntx_init();

	if (!json_db_update())
	{
        DB_CNTX_T *p_db_cntx = db_get_cntx();
        
        p_db_cntx->p_db_inst = db_inst_create(p_db_cntx->conn_info.db_type);
        if (p_db_cntx->p_db_inst)
        {
            db_set_conn_info(
                p_db_cntx->p_db_inst,
                p_db_cntx->conn_info.db_host,
                p_db_cntx->conn_info.db_port,
                p_db_cntx->conn_info.db_user,
                p_db_cntx->conn_info.db_pw,
                p_db_cntx->conn_info.db_name,
                p_db_cntx->conn_info.db_sock,
                p_db_cntx->conn_info.db_pw_path,
                p_db_cntx->conn_info.db_seed_path
            );

            
            DB_TRUNCATE();
        }
        else
        {
            ASSERT_M(0);
        }
	}
}

