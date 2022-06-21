/**
    @file main.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

#if (MEM_BLK_USE == ENABLED)
extern void malloc_init(void);
#endif // MEM_BLK_USE

//extern void cons_fee_test(void);

void node_info(void)
{
    //#define FLOAT_POINT 10000
    int32_t main_ver_num, sub_ver_num;

    //
    main_ver_num = ATOI_M(VER_INFO_MAIN);

    //
    sub_ver_num = ATOI_M(VER_INFO_SUB);

    //
    DBG_PRINT (DBG_APP, DBG_CLEAR, (void *)"==================================================\n");
    DBG_PRINT (DBG_APP, DBG_CLEAR, (void *)"= FINL Block Chain                               =\n");
    DBG_PRINT (DBG_APP, DBG_CLEAR, (void *)"=  [ Ver  : %01d.%04d ]                             =\n", main_ver_num, sub_ver_num);
    DBG_PRINT (DBG_APP, DBG_CLEAR, (void *)"==================================================\n");

    //
    openssl_get_version();

//    cons_fee_test();
//    ASSERT_M(0);
}

int main (int argc, char *argv[])
{
    int status;

    //
	addSignal(argv[0]);

#if (MEM_BLK_USE == ENABLED)
    //
    malloc_init();

#if (MEM_BLK_TEST == ENABLED)
    mem_test();
#endif // MEM_BLK_TEST
#endif // MEM_BLK_USE

    //
    DBG_INIT(true);

    //
    node_info();

    //
    util_init(true);

    //
    openssl_init_v();

    //
    timer_init();

    // Create Thread
    cli_task_init();
    
    rx_task_init();
    tx_task_init();
    p2p_task_init();
    cons_task_init();
    db_task_init();
#if defined (USE_DB_REDIS)
    redis_task_init();
#endif // USE_DB_REDIS

    //
    task_set_pid_nice();
    task_set_tid_nice();

    // Create Thread
    if(!(ATOI_M(RELEASE_MODE)))
    {
        pthread_create (&g_pthread_id[CLI_THREAD_IDX], NULL, t_cli_main, (void *)"CLI");
    }
    
    pthread_create (&g_pthread_id[RX_THREAD_IDX], NULL, t_rx_main, (void *)"RX");
    pthread_create (&g_pthread_id[TX_THREAD_IDX], NULL, t_tx_main, (void *)"TX");
    pthread_create (&g_pthread_id[P2P_THREAD_IDX], NULL, t_p2p_main, (void *)"P2P");
    pthread_create (&g_pthread_id[CONS_THREAD_IDX], NULL, t_cons_main, (void *)"CONS");
    pthread_create (&g_pthread_id[DB_THREAD_IDX], NULL, t_db_main, (void *)"DB");
#if defined (USE_DB_REDIS)
    pthread_create (&g_pthread_id[DB_REDIS_THREAD_IDX], NULL, t_redis_main, (void *)"DB_REDIS");
#endif // USE_DB_REDIS

    // Join Thread
    pthread_join(g_pthread_id[CLI_THREAD_IDX], (void **)&status);
    pthread_join(g_pthread_id[RX_THREAD_IDX], (void **)&status);
    pthread_join(g_pthread_id[TX_THREAD_IDX], (void **)&status);
    pthread_join(g_pthread_id[P2P_THREAD_IDX], (void **)&status);
    pthread_join(g_pthread_id[CONS_THREAD_IDX], (void **)&status);
    pthread_join(g_pthread_id[DB_THREAD_IDX], (void **)&status);
#if defined (USE_DB_REDIS)
    pthread_join(g_pthread_id[DB_REDIS_THREAD_IDX], (void **)&status);
#endif // USE_DB_REDIS

    // End Thread
    return 0;
}

