/**
    @file db_mongodb.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

void mongodb_get_svr_version(void)
{
    DBG_PRINT(DBG_DB, DBG_INFO, (void *)"MONGOD Ver: \n");
}

void mongodb_get_cli_version(void)
{
    DBG_PRINT(DBG_DB, DBG_INFO, (void *)"MONGOC Ver: %s\n", mongoc_get_version());
}

#ifdef   _UNIT_TEST_
static void  mongodb_print_bson(const bson_t *p_bson, const char *p_title)
{
    char *p_str = bson_as_json(p_bson, NULL);

#ifdef  _UNIT_TEST_
    printf("[32m(%s)[0m:[33m%s[0m\n", p_title, p_str);
#else
    DBG_PRINT(DBG_CLI, DBG_TRACE, (void *)"(%s):%s\n", p_title, p_str);
#endif

    bson_free (p_str);
}
#endif // _UNIT_TEST_

static MONGODB_INST_MGR_T *mongodb_create_inst_mgr(void)
{
    MONGODB_INST_MGR_T  *p_mgr = NULL;

    DBG_PRINT(DBG_CLI, DBG_TRACE, (void *)"%s\n", __FUNCTION__);

    p_mgr  = (MONGODB_INST_MGR_T *)MALLOC_M(sizeof(MONGODB_INST_MGR_T));
    ASSERT_M(p_mgr);

    pthread_mutex_init(&(p_mgr->inst_get_mtx), NULL);
    pthread_cond_init(&(p_mgr->inst_get_cond), NULL);

    return (p_mgr);
}

static void mongodb_destroy_collections(MONGODB_INST_T **pp_inst)
{
    DBG_PRINT(DBG_CLI, DBG_TRACE, (void *)"%s\n", __FUNCTION__);

    if (pp_inst && *pp_inst)
    {
        if ((*pp_inst)->p_txs)  { mongoc_collection_destroy((*pp_inst)->p_txs); }
        if ((*pp_inst)->p_info) { mongoc_collection_destroy((*pp_inst)->p_info); }
        if ((*pp_inst)->p_contents){ mongoc_collection_destroy((*pp_inst)->p_contents); }
        if ((*pp_inst)->p_prv_contents){ mongoc_collection_destroy((*pp_inst)->p_prv_contents); }
    }	
}

static void mongodb_destroy_inst(MONGODB_INST_T **pp_inst)
{
    DBG_PRINT(DBG_CLI, DBG_TRACE, (void *)"%s\n", __FUNCTION__);

    if (pp_inst && *pp_inst)
    {
        mongodb_destroy_collections(pp_inst);

        if ((*pp_inst)->p_db)       { mongoc_database_destroy((*pp_inst)->p_db); }
        if ((*pp_inst)->p_client)   { mongoc_client_destroy((*pp_inst)->p_client); }
        if ((*pp_inst)->p_bulk)     { mongoc_bulk_operation_destroy((*pp_inst)->p_bulk); }

        FREE_M (*pp_inst); 
        //(*pp_inst) = NULL;
    }
}

static void mongodb_destroy_inst_mgr(MONGODB_INST_MGR_T **pp_mgr)
{
    DBG_PRINT(DBG_CLI, DBG_TRACE, (void *)"%s\n", __FUNCTION__);

    if (!pp_mgr || !(*pp_mgr))
    {
        return;
    }

    mongodb_destroy_inst(&((*pp_mgr)->p_inst));

    pthread_cond_destroy(&((*pp_mgr)->inst_get_cond));
    pthread_mutex_destroy(&((*pp_mgr)->inst_get_mtx));

    FREE_M(*pp_mgr);

    (*pp_mgr) = NULL;
}

DB_RESULT_E mongodb_insert_doc(mongoc_collection_t *p_collection)
{
    bson_t doc;
    bson_oid_t oid;
    bson_error_t error;
    bool ret;

    /* insert a document */
    bson_init (&doc);
    bson_oid_init (&oid, NULL);
    BSON_APPEND_OID (&doc, "_id", &oid);

    ret = mongoc_collection_insert (p_collection, MONGOC_INSERT_NONE, &doc, NULL, &error);
    if (!ret)
    {
       DBG_PRINT(DBG_CLI, DBG_ERROR, (void *)"%s\n", error.message);
       return (DB_RESULT_FAILURE);
    }

    bson_destroy (&doc);

    return (DB_RESULT_SUCCESS);
}

DB_RESULT_E mongodb_create_index(mongoc_database_t *p_db, const char *p_collection_name, const char *p_idx_field, bool b_is_unique, int32_t order)
{
    bson_error_t      error;

    DBG_PRINT(DBG_CLI, DBG_TRACE, (void *)"%s\n", __FUNCTION__);

    do
    { /**  create index  **/
        bson_t   keys;
        bson_t   reply;
        bson_t   *p_create_idxes = NULL;
        int32_t  ret = 0;

        char idx_name[MONGODB_IDX_NAME_STR_SIZE];
        //char *p_idx_name;

        bson_init (&keys);
        if (order)
        {
            ASSERT_M((order == MONGODB_ASCENDING_ORDER) || (order == MONGODB_DESCENDING_ORDER));
            BSON_APPEND_INT32(&keys, p_idx_field, MONGODB_ASCENDING_ORDER);
        }
        else
        {
            ASSERT_M(0);
        }

        sprintf(idx_name, "%s_", p_idx_field);
        //p_idx_name  = mongoc_collection_keys_to_index_string (&keys);
        
        if (b_is_unique)
        {
            p_create_idxes  = BCON_NEW (
                "createIndexes", BCON_UTF8 (p_collection_name),
                    "indexes", "[", "{",
                        "key",     BCON_DOCUMENT (&keys),
                        "name",    BCON_UTF8 (idx_name),
                        "unique",  "true",
                    "}", "]"
                );
        }
        else
        {
            p_create_idxes  = BCON_NEW (
                "createIndexes", BCON_UTF8 (p_collection_name),
                    "indexes", "[", "{",
                        "key",     BCON_DOCUMENT (&keys),
                        "name",    BCON_UTF8 (idx_name),
                    "}", "]"
                );
        }

        ret = mongoc_database_write_command_with_opts (p_db, p_create_idxes, NULL /* opts */, &reply, &error);

#ifdef   _UNIT_TEST_
        mongodb_print_bson(p_create_idxes, "Create index");
#endif
        if (!ret)
        {
            DBG_PRINT(DBG_CLI, DBG_ERROR, (void *)"Error in createIndexes: %s\n", error.message);
        }

#ifdef  _UNIT_TEST_
        mongodb_print_bson(&reply, "Create index reply:");
#endif
        //bson_free (p_idx_name);
        bson_destroy (p_create_idxes);
        bson_destroy (&reply);
        bson_destroy (&keys);
    } while(0);

    // mongoc_collection_create_index()
    // mongoc_collection_create_index_with_opts()

    return (DB_RESULT_SUCCESS);
}

#define URL_STR_SIZE 1024
DB_RESULT_E mongodb_conn_init(void **pp_mgr, uint16_t mgr_cnt, char *p_db_host, uint16_t db_port, char *p_db_user, char *p_db_pw, char *p_db_name, char *p_db_sock)
{
    char                uri_string[URL_STR_SIZE];
    mongoc_uri_t        *p_uri        = NULL;
    mongoc_client_t     *p_client     = NULL;
    bson_error_t        error;

    MONGODB_INST_MGR_T  *p_mgr        = NULL;

    DBG_PRINT(DBG_CLI, DBG_TRACE, (void *)"%s\n", __FUNCTION__);

    p_mgr  = mongodb_create_inst_mgr();

    if (NULL == p_db_pw || 0x00 == p_db_pw[0])
    {
        snprintf(uri_string, URL_STR_SIZE, "mongodb://%s@%s:%d", p_db_user, p_db_host, db_port);
    }
    else
    {
        snprintf(uri_string, URL_STR_SIZE, "mongodb://%s:%s@%s:%d", p_db_user, p_db_pw, p_db_host, db_port);
    }

    DBG_PRINT(DBG_CLI, DBG_INFO, (void *)"ar_ppMgrect to %s(ar_ppMgr count: %d)\n", uri_string, mgr_cnt);

    mongoc_init();

    p_uri = mongoc_uri_new_with_error (uri_string, &error);
    if (!p_uri) 
    {
        DBG_PRINT(DBG_DB, DBG_ERROR, (void *)
            "failed to parse URI: %s\n"
            "error message:       %s\n",
            uri_string,
            error.message);

        FREE_M(p_mgr);

        return (DB_RESULT_FAILURE);
    }

    do
    {
        char  app_name[8] = "mn#";

        MONGODB_INST_T *p_new_inst = NULL;

        p_new_inst  = (MONGODB_INST_T*)MALLOC_M(sizeof(MONGODB_INST_T));
        ASSERT_M(p_new_inst);

        p_client  = mongoc_client_new_from_uri (p_uri);
        if (!p_client) 
        {
            FREE_M(p_new_inst);
            mongodb_destroy_inst_mgr(&p_mgr);
            DBG_PRINT(DBG_DB, DBG_ERROR, (void *)"failed to parse URI: client open fail\n");
            return (DB_RESULT_FAILURE);
        }
        mongoc_client_set_appname( p_client, app_name );

//#ifdef  _UNIT_TEST_
        {
            bson_t *command, reply;
            char   *str;
            int     retval;

            command = BCON_NEW ("ping", BCON_INT32 (1));

            retval = mongoc_client_command_simple (p_client, "admin", command, NULL, &reply, &error);

            if (!retval)
            {
                DBG_PRINT(DBG_DB, DBG_ERROR, (void *)"ping test fail: %s\n", error.message);
                return (DB_RESULT_FAILURE);
            }

            str = bson_as_json (&reply, NULL);
            DBG_PRINT(DBG_DB, DBG_INFO, (void *)"ping test result: %s\n", str);

            FREE_M(str);
            bson_destroy(&reply);
            bson_destroy(command);
        }
//#endif

        p_new_inst->p_client    = p_client;
        p_new_inst->p_db        = mongoc_client_get_database   (p_client, p_db_name);
        p_new_inst->p_blk_txs       = mongoc_client_get_collection (p_client, p_db_name, "blk_txs");
        p_new_inst->p_blk_info      = mongoc_client_get_collection (p_client, p_db_name, "blk_info");
        p_new_inst->p_blk_contents  = mongoc_client_get_collection (p_client, p_db_name, "blk_contents");

        p_mgr->p_inst  = p_new_inst;

        p_mgr->inst_cnt       = mgr_cnt;
    } while(0);

    mongoc_uri_destroy(p_uri);

    //DB_GET_SVR_VERSION();
    DB_GET_CLI_VERSION();

    mongodb_create_index(p_mgr->p_inst->p_db, "blk_txs",      DB_DB_KEY_STR,  true,  MONGODB_ASCENDING_ORDER);
    mongodb_create_index(p_mgr->p_inst->p_db, "blk_txs",      DB_BLK_NUM_STR, false, MONGODB_ASCENDING_ORDER);
    mongodb_create_index(p_mgr->p_inst->p_db, "blk_info",     DB_BLK_NUM_STR, true,  MONGODB_ASCENDING_ORDER);
    mongodb_create_index(p_mgr->p_inst->p_db, "blk_contents", DB_BLK_NUM_STR, true,  MONGODB_ASCENDING_ORDER);

    *pp_mgr  = p_mgr;

    return (DB_RESULT_SUCCESS);
}

void mongodb_conn_close(void **pp_mgr)
{
    DBG_PRINT(DBG_CLI, DBG_TRACE, (void *)"%s\n", __FUNCTION__);

    if (pp_mgr && *pp_mgr)
    {
        mongodb_destroy_inst_mgr((MONGODB_INST_MGR_T**)pp_mgr);
    }

    mongoc_cleanup ();
}

static void mongodb_truncate_collections(MONGODB_INST_T **pp_inst)
{
    DBG_PRINT(DBG_CLI, DBG_TRACE, (void *)"%s\n", __FUNCTION__);

    if (pp_inst && *pp_inst)
    {
        bson_t query;
        bson_t reply;
        bson_error_t error;
        
        bson_init (&query);

        if ((*pp_inst)->p_blk_txs)       
        {
            mongoc_collection_delete_many((*pp_inst)->p_blk_txs, &query, NULL, &reply, &error); 
        }

        if ((*pp_inst)->p_blk_info)       
        {
            mongoc_collection_delete_many((*pp_inst)->p_blk_info, &query, NULL, &reply, &error); 
        }

        if ((*pp_inst)->p_blk_contents)       
        {
            mongoc_collection_delete_many((*pp_inst)->p_blk_contents, &query, NULL, &reply, &error); 
        }
    }	
}

DB_RESULT_E mongodb_truncate(void)
{
#if (DB_TRUNCATE_TABLES == ENABLED)
    MONGODB_INST_MGR_T  *p_mgr  = (MONGODB_INST_MGR_T*)db_get_db_inst_mgr();
	MONGODB_INST_T      *p_inst;

    DBG_PRINT(DBG_CLI, DBG_TRACE, (void *)"%s\n", __FUNCTION__);

    p_inst = p_mgr->p_inst;
    
    mongodb_truncate_collections(&(p_inst));
#endif // DB_TRUNCATE_TABLES
    return (DB_RESULT_SUCCESS);
}

// Not Used Function
DB_RESULT_E mongodb_drop_collection(char *p_host, uint16_t port, char *p_user, char *p_pw, char *p_db_name, char *p_collection_name)
{
    char                 uri_string[URL_STR_SIZE];
    mongoc_uri_t         *p_uri        = NULL;
    mongoc_client_t      *p_client     = NULL;
    mongoc_database_t    *p_db         = NULL;
    mongoc_collection_t  *p_col        = NULL;
    bson_error_t         error;
    DB_RESULT_E          ret           = DB_RESULT_FAILURE;

    DBG_PRINT(DBG_CLI, DBG_TRACE, (void *)"%s\n", __FUNCTION__);

    if (NULL == p_pw || 0x00 == p_pw[0])
    {
        snprintf(uri_string, URL_STR_SIZE, "mongodb://%s@%s:%d", p_user, p_host, port);
    }
    else
    {
        snprintf(uri_string, URL_STR_SIZE, "mongodb://%s:%s@%s:%d/%s", p_user, p_pw, p_host, port, p_db_name);
    }

#ifdef  _UNIT_TEST_
    printf("[INFO] connect to %s\n", uri_string);
#endif

    mongoc_init();

    p_uri = mongoc_uri_new_with_error (uri_string, &error);
    if (!p_uri) 
    {
        DBG_PRINT (DBG_DB, DBG_ERROR, (void *)
            "failed to parse URI: %s\n"
            "error message:       %s\n",
            uri_string,
            error.message);

        return (ret);
    }

    do
    {
        p_client  = mongoc_client_new_from_uri (p_uri);
        if (!p_client) 
        {
            DBG_PRINT (DBG_DB, DBG_ERROR, (void *)"failed to parse URI: client open fail. %s, %s\n", uri_string, error.message);

            break;
        }
        
        mongoc_client_set_appname( p_client, "collectionDrop" );

        do
        {
            p_db = mongoc_client_get_database(p_client, p_db_name);
            if (!p_db)
            {
                DBG_PRINT (DBG_DB, DBG_ERROR, (void *)"%s database get fail. %s\n", p_db_name, error.message);
                break;
            }

            do
            {
                p_col  = mongoc_client_get_collection (p_client, p_db_name, p_collection_name);
                if (!p_col)
                {
                    DBG_PRINT (DBG_DB, DBG_ERROR, (void *)"%s collection get fail. %s\n", p_db_name, error.message);
                    break;
                }

                do
                {
                    if (mongoc_collection_drop(p_col, &error))
                    {
                        DBG_PRINT (DBG_DB, DBG_ERROR, (void *) "%s collection drop fail. %s\n", p_collection_name, error.message);
                        break;
                    }

                    mongoc_collection_destroy(p_col);

                    ret = DB_RESULT_SUCCESS;
                } while(0);
            } while(0);

            mongoc_database_destroy(p_db);
        } while (0);

        mongoc_client_destroy(p_client);
    } while(0);

    mongoc_uri_destroy(p_uri); //

    return (ret);
}

// Insert Table - block DB
DB_RESULT_E  mongodb_insert_t_blk_tx(uint64_t blk_num, uint64_t db_key, uint8_t *p_sc_hash)
{
    DB_RESULT_E          ret  = DB_RESULT_SUCCESS; 
    MONGODB_INST_MGR_T  *p_mgr  = (MONGODB_INST_MGR_T*)db_get_db_inst_mgr();
    MONGODB_INST_T      *p_inst = NULL;
    bson_t            transaction;
    bson_error_t      error;

    DBG_PRINT(DBG_CLI, DBG_TRACE, (void *)"%s\n", __FUNCTION__);

    p_inst = p_mgr->p_inst;

    if (NULL == p_inst)
    {
        DBG_PRINT (DBG_DB, DBG_ERROR, (void *)"Mongodb Instance getting fail.(all instance busy)\n");
        ret = DB_RESULT_INSTANCE_GET_FAILURE;

        return (ret);
    }

    bson_init (&transaction);
    
    do
    { /** transaction setup **/
        P2P_CNTX_T *p_p2p_cntx = p2p_get_cntx();
        uint16_t subnet_id = p_p2p_cntx->my_uniq_addr;

        BSON_ASSERT (bson_append_int32(&transaction, DB_SUBNET_ID_STR, DB_SUBNET_ID_STR_SIZE, subnet_id));
        BSON_ASSERT (bson_append_int64(&transaction, DB_BLK_NUM_STR, DB_BLK_NUM_STR_SIZE, blk_num));
        BSON_ASSERT (bson_append_int64(&transaction, DB_DB_KEY_STR, DB_DB_KEY_STR_SIZE,  db_key));
        BSON_ASSERT (bson_append_utf8(&transaction, DB_SC_HASH_STR, DB_SC_HASH_STR_SIZE,  (char *)p_sc_hash, HASH_SIZE));
        
#ifdef   _UNIT_TEST_
        mongodb_print_bson(&transaction, "Transaction");
#endif

        if (!mongoc_collection_insert_one (p_inst->p_blk_txs, &transaction, NULL, NULL, &error))
        {
            DBG_PRINT (DBG_DB, DBG_ERROR, (void *)"%s\n", error.message);
            ret  = DB_RESULT_FAILURE;

            break;
        }
    } while (0);

    bson_destroy(&transaction);

    return (ret);
}

void *mongodb_insert_t_blk_tx_start(uint32_t len)
{
	MONGODB_INST_MGR_T  *p_mgr  = (MONGODB_INST_MGR_T*)db_get_db_inst_mgr();
	MONGODB_INST_T      *p_inst;

    DBG_PRINT(DBG_CLI, DBG_TRACE, (void *)"%s\n", __FUNCTION__);

    p_inst = p_mgr->p_inst;
    
	if (NULL == p_inst)
	{
		DBG_PRINT (DBG_DB, DBG_ERROR, (void *)"Mongodb Instance getting fail.(all instance busy)\n");
		return (NULL);
	}

#ifdef   _UNIT_TEST_
	DBG_PRINT(DBG_CLI, DBG_INFO, (void *)"Transaction(bulk) start\n");
#endif

	p_inst->p_bulk = mongoc_collection_create_bulk_operation_with_opts (p_inst->p_blk_txs, NULL);

	return ((void*)p_inst);
}

DB_RESULT_E mongodb_insert_t_blk_tx_process(void *p_arg, bool b_last, uint64_t blk_num, uint64_t db_key, uint8_t *p_sc_hash)
{
    MONGODB_INST_T *p_inst = (MONGODB_INST_T*)p_arg;
    bson_t transaction;

    DBG_PRINT(DBG_CLI, DBG_TRACE, (void *)"%s\n", __FUNCTION__);

    bson_init (&transaction);

    do
    { /** transaction setup **/
        P2P_CNTX_T *p_p2p_cntx = p2p_get_cntx();
        uint16_t subnet_id = p_p2p_cntx->my_uniq_addr;
        
        BSON_ASSERT (bson_append_int32(&transaction, DB_SUBNET_ID_STR, DB_SUBNET_ID_STR_SIZE, subnet_id));
        BSON_ASSERT (bson_append_int64(&transaction, DB_BLK_NUM_STR, DB_BLK_NUM_STR_SIZE, blk_num));
        BSON_ASSERT (bson_append_int64(&transaction, DB_DB_KEY_STR, DB_DB_KEY_STR_SIZE,  db_key));
        BSON_ASSERT (bson_append_utf8(&transaction, DB_SC_HASH_STR, DB_SC_HASH_STR_SIZE,  (char *)p_sc_hash, HASH_SIZE));

#ifdef   _UNIT_TEST_
        {
            char  str[128];

            snprintf(str, 64, "Transaction(bulk) add");
            mongodb_print_bson(&transaction, str);
        }
#endif

        mongoc_bulk_operation_insert(p_inst->p_bulk, &transaction);
    } while (0);

    bson_destroy(&transaction);

    return (DB_RESULT_SUCCESS);
}

DB_RESULT_E mongodb_insert_t_blk_tx_end(void *p_arg)
{
    MONGODB_INST_T      *p_inst = (MONGODB_INST_T*)p_arg;
    DB_RESULT_E          ret    = DB_RESULT_SUCCESS;
    bson_error_t      error;
    bson_t            reply;

    DBG_PRINT(DBG_CLI, DBG_TRACE, (void *)"%s\n", __FUNCTION__);

    if (!mongoc_bulk_operation_execute (p_inst->p_bulk, &reply, &error))
    {
        DBG_PRINT (DBG_DB, DBG_ERROR, (void *)"bulk insert tx execute fail %s\n", error.message);
        ret = DB_RESULT_FAILURE;
    }

#ifdef   _UNIT_TEST_
    {
        char  str[128];

        snprintf(str, 64, "Transaction(bulk) done, print reply");
        mongodb_print_bson(&reply, str);
    }
#endif

    bson_destroy (&reply);
    mongoc_bulk_operation_destroy (p_inst->p_bulk);
    p_inst->p_bulk  = NULL;

    return (ret);
}

DB_RESULT_E  mongodb_insert_t_info(uint64_t blk_num)
{
    DB_RESULT_E          ret  = DB_RESULT_SUCCESS; 
    MONGODB_INST_MGR_T  *p_mgr  = (MONGODB_INST_MGR_T*)db_get_db_inst_mgr();
    MONGODB_INST_T      *p_inst = NULL;
    bson_t            blk_info;
    bson_error_t      error;

    DBG_PRINT(DBG_CLI, DBG_TRACE, (void *)"%s\n", __FUNCTION__);

    p_inst = p_mgr->p_inst;

    if (NULL == p_inst)
    {
        DBG_PRINT (DBG_DB, DBG_ERROR, (void *)"Mongodb Instance getting fail.(all instance busy)\n");

        return (DB_RESULT_INSTANCE_GET_FAILURE);
    }

    bson_init (&blk_info);

    do
    { /** block setup **/
        uint16_t subnet_id;
#if (CONS_USE_SUBNET_ID == ENABLED)
        subnet_id = CONS_GET_SUBNET_ID(blk_num);
#else
        P2P_CNTX_T *p_p2p_cntx = p2p_get_cntx();

        subnet_id = p_p2p_cntx->my_uniq_addr;
#endif // CONS_USE_SUBNET_ID

        // Status and Confirm time set default value(0)
        BSON_ASSERT (bson_append_int64(&blk_info, DB_SUBNET_ID_STR, DB_SUBNET_ID_STR_SIZE, subnet_id));
        BSON_ASSERT (bson_append_int64(&blk_info, DB_BLK_NUM_STR, DB_BLK_NUM_STR_SIZE, blk_num )); // for sharding.
        BSON_ASSERT (bson_append_int32(&blk_info, DB_STATUS_STR, DB_STATUS_STR_SIZE,  0));
        BSON_ASSERT (bson_append_int64(&blk_info, DB_BCT_STR, DB_BCT_STR_SIZE,  0));

#ifdef   _UNIT_TEST_
        mongodb_print_bson(&blk_info, "blk_info");
#endif
        if (!mongoc_collection_insert_one (p_inst->p_blk_info, &blk_info, NULL, NULL, &error))
        {
            DBG_PRINT (DBG_DB, DBG_ERROR, (void *)"%s\n", error.message);
            ret  = DB_RESULT_FAILURE;

            break;
        }

    } while(0);

    bson_destroy(&blk_info);

    return (ret);
}

DB_RESULT_E  mongodb_insert_t_blk_contents(CONS_LIGHT_BLK_T *p_light_blk)
{
    DB_RESULT_E          ret  = DB_RESULT_SUCCESS; 
    MONGODB_INST_MGR_T  *p_mgr  = (MONGODB_INST_MGR_T*)db_get_db_inst_mgr();
    MONGODB_INST_T      *p_inst = NULL;
    bson_t            light_blk;
    bson_error_t      error;

    DBG_PRINT(DBG_CLI, DBG_TRACE, (void *)"%s\n", __FUNCTION__);

    p_inst = p_mgr->p_inst;

    if (NULL == p_inst)
    {
        DBG_PRINT (DBG_DB, DBG_ERROR, (void *)"Mongodb Instance getting fail.(all instance busy)\n");
        return (DB_RESULT_INSTANCE_GET_FAILURE);
    }
    
    bson_init (&light_blk);
    
    do
    {
        uint16_t subnet_id;
#if (CONS_USE_SUBNET_ID == ENABLED)
        subnet_id = CONS_GET_SUBNET_ID(p_light_blk->blk_num);
#else
        P2P_CNTX_T *p_p2p_cntx = p2p_get_cntx();

        subnet_id = p_p2p_cntx->my_uniq_addr;
#endif // CONS_USE_SUBNET_ID

        BSON_ASSERT (bson_append_int32(&light_blk, DB_SUBNET_ID_STR, DB_SUBNET_ID_STR_SIZE, subnet_id));
        BSON_ASSERT (bson_append_int64(&light_blk, DB_BLK_NUM_STR, DB_BLK_NUM_STR_SIZE, p_light_blk->blk_num));
        BSON_ASSERT (bson_append_int64(&light_blk, DB_P2P_ADDR_STR, DB_P2P_ADDR_STR_SIZE,  p_light_blk->p2p_addr));
        BSON_ASSERT (bson_append_int64(&light_blk, DB_BGT_STR, DB_BGT_STR_SIZE,  p_light_blk->bgt));
        BSON_ASSERT (bson_append_utf8(&light_blk, DB_PBH_STR, DB_PBH_STR_SIZE,  (char*)p_light_blk->pbh, HASH_SIZE));
        BSON_ASSERT (bson_append_int32(&light_blk, DB_TX_CNT_STR, DB_TX_CNT_STR_SIZE,  p_light_blk->tx_cnt));
        BSON_ASSERT (bson_append_utf8(&light_blk, DB_BLK_HASH_STR, DB_BLK_HASH_STR_SIZE,  (char*)p_light_blk->blk_hash, HASH_SIZE));
        BSON_ASSERT (bson_append_utf8(&light_blk, DB_SIG_STR, DB_SIG_STR_SIZE,  (char*)p_light_blk->sig, SIG_SIZE));
        BSON_ASSERT (bson_append_utf8(&light_blk, DB_SIG_PUBKEY_STR, DB_SIG_PUBKEY_STR_SIZE,  (char*)p_light_blk->sig_pubkey, COMP_PUBKEY_SIZE));

#ifdef   _UNIT_TEST_
        mongodb_print_bson(&light_blk, "light_blk");
#endif
        if (!mongoc_collection_insert_one (p_inst->p_blk_contents, &light_blk, NULL, NULL, &error))
        {
            DBG_PRINT (DBG_DB, DBG_ERROR, (void *)"%s\n", error.message);
            ret  = DB_RESULT_FAILURE;

            break;
        }
    } while(0);

    bson_destroy(&light_blk);

    mongodb_insert_t_info(p_light_blk->blk_num);

    return (ret);
}

// Update Table - block DB
DB_RESULT_E  mongodb_update_bn_t_blk_txs_w_dk(uint64_t db_key, uint64_t blk_num)
{
    DB_RESULT_E         ret  = DB_RESULT_FAILURE; 
    MONGODB_INST_MGR_T *p_mgr  =(MONGODB_INST_MGR_T*)db_get_db_inst_mgr();
    MONGODB_INST_T     *p_inst = NULL;
    bson_error_t        error;

    DBG_PRINT(DBG_CLI, DBG_TRACE, (void *)"%s\n", __FUNCTION__);

    p_inst = p_mgr->p_inst;

    if (NULL == p_inst)
    {
        DBG_PRINT (DBG_DB, DBG_ERROR, (void *)"Mongodb Instance getting fail.(all instance busy)\n");

        return (DB_RESULT_INSTANCE_GET_FAILURE);
    }

    do
    { /** Update transaction **/
        bson_t  *p_query;
        bson_t  *p_update;

        p_query   = BCON_NEW (DB_DB_KEY_STR, BCON_INT64 (db_key));
        p_update  = BCON_NEW ("$set", "{", DB_BLK_NUM_STR,   BCON_INT64(blk_num), "}");

#ifdef   _UNIT_TEST_
        mongodb_print_bson(p_query,  "Transaction Update(key)");
        mongodb_print_bson(p_update, "Transaction Update(query)");
#endif

        if(mongoc_collection_update (p_inst->p_blk_txs, MONGOC_UPDATE_NONE, p_query, p_update, NULL, &error))
        {
            ret = DB_RESULT_SUCCESS;
        }

        bson_destroy(p_query);
        bson_destroy(p_update);
    } while(0);

    return (ret);
}

DB_RESULT_E  mongodb_update_status_t_blk_info_w_bn(uint64_t blk_num, uint64_t status, uint64_t blk_cfm_time)
{
    DB_RESULT_E         ret  = DB_RESULT_FAILURE; 
    MONGODB_INST_MGR_T *p_mgr  = (MONGODB_INST_MGR_T*)db_get_db_inst_mgr();
    MONGODB_INST_T     *p_inst = NULL;
    bson_error_t        error;

    DBG_PRINT(DBG_CLI, DBG_TRACE, (void *)"%s\n", __FUNCTION__);

    p_inst = p_mgr->p_inst;

    if (NULL == p_inst)
    {
        DBG_PRINT (DBG_DB, DBG_ERROR, (void *)"Mongodb Instance getting fail.(all instance busy)\n");

        return (DB_RESULT_INSTANCE_GET_FAILURE);
    }

    do
    { /** Update block **/
        bson_t  query;
        bson_t  update;
        bson_t  updateBody;

        bson_init (&query);
        bson_init (&update);
        bson_init (&updateBody);

        BSON_ASSERT (bson_append_int64 (&query, DB_BLK_NUM_STR, DB_BLK_NUM_STR_SIZE, blk_num));
        if (status) { BSON_ASSERT (bson_append_int64( &updateBody, DB_STATUS_STR, DB_STATUS_STR_SIZE, status)); }
        if (blk_cfm_time) { BSON_ASSERT (bson_append_int64( &updateBody, DB_BCT_STR, DB_BCT_STR_SIZE, blk_cfm_time)); }
        BSON_ASSERT (bson_append_document(&update, "$set", 4, &updateBody));

#ifdef   _UNIT_TEST_
        mongodb_print_bson(&query,  "Block Update(key)");
        mongodb_print_bson(&update, "Block Update(query)");
#endif

        if(mongoc_collection_update (p_inst->p_blk_info, MONGOC_UPDATE_NONE, &query, &update, NULL, &error))
        {
            ret = DB_RESULT_SUCCESS;
        }

        bson_destroy (&query);
        bson_destroy (&update);
        bson_destroy (&updateBody);
    } while(0);

    return (ret);
}

// Select Table - block DB
DB_RESULT_E  mongodb_select_xor_txs_f_blk_txs_w_bn(DB_TX_FIELD_T *p_db_tx)
{
    MONGODB_INST_MGR_T *p_mgr   = (MONGODB_INST_MGR_T*)db_get_db_inst_mgr();
    MONGODB_INST_T     *p_inst  = NULL;

    DBG_PRINT(DBG_CLI, DBG_TRACE, (void *)"%s\n", __FUNCTION__);

    // Init as All ZERO
    MEMSET_M(&p_db_tx->db_key, 0x0, DB_KEY_SIZE);
    MEMSET_M(p_db_tx->sc_hash, 0x0, HASH_SIZE);

    p_inst = p_mgr->p_inst;

    if (NULL == p_inst)
    {
        DBG_PRINT (DBG_DB, DBG_ERROR, (void *)"Mongodb Instance getting fail.(all instance busy)\n");

        return (DB_RESULT_INSTANCE_GET_FAILURE);
    }

    do
    {
        bson_t *p_filter = BCON_NEW (DB_BLK_NUM_STR, BCON_INT64 (p_db_tx->blk_num));
        bson_t *p_opts   = BCON_NEW (
            "projection", "{",
                DB_DB_KEY_STR, BCON_BOOL (true),
                DB_SC_HASH_STR,  BCON_BOOL (true),
                "_id",   BCON_BOOL (false),
            "}"
            );

        mongoc_cursor_t  *p_cursor = mongoc_collection_find_with_opts (p_inst->p_blk_txs, p_filter, p_opts, NULL);

        const bson_t  *p_doc;
        bson_iter_t   iter;

        if (mongoc_cursor_next (p_cursor, &p_doc) && bson_iter_init (&iter, p_doc))
        {
            while (bson_iter_next(&iter))
            {
                const char *key = bson_iter_key (&iter);

                if ('D' == key[0])
                {
                    uint64_t ret_db_key = bson_iter_int64(&iter);
                    xor_m(&(p_db_tx->db_key), &(p_db_tx->db_key), &ret_db_key, DB_KEY_SIZE);
                }
                else
                {
                    char sc_hash[HASH_SIZE];

                    MEMCPY_M(sc_hash, bson_iter_utf8(&iter, NULL), HASH_SIZE);
                    xor_m(p_db_tx->sc_hash, p_db_tx->sc_hash, sc_hash, HASH_SIZE);
                }
            }
        }

        mongoc_cursor_destroy (p_cursor);
        bson_destroy (p_opts);
        bson_destroy (p_filter);
    } while(0);

    return (DB_RESULT_SUCCESS);
}

uint32_t mongodb_select_count_f_blk_txs_w_bn(uint64_t blk_num)
{
    MONGODB_INST_MGR_T *p_mgr   = (MONGODB_INST_MGR_T*)db_get_db_inst_mgr();
    MONGODB_INST_T     *p_inst  = NULL;
    int64_t             count  = 0;

    DBG_PRINT(DBG_CLI, DBG_TRACE, (void *)"%s\n", __FUNCTION__);

    p_inst = p_mgr->p_inst;

    if (NULL == p_inst)
    {
        DBG_PRINT (DBG_DB, DBG_ERROR, (void *)"Mongodb Instance getting fail.(all instance busy)\n");

        return (DB_RESULT_INSTANCE_GET_FAILURE);
    }

    do
    {
        bson_t          query;
        bson_error_t    error;

        bson_init(&query);
        bson_append_int64(&query, DB_BLK_NUM_STR, DB_BLK_NUM_STR_SIZE, blk_num);

        count  = mongoc_collection_count_documents (p_inst->p_blk_txs, &query, NULL, NULL, NULL, &error);
        if (count < 0)
        {
            DBG_PRINT (DBG_DB, DBG_ERROR, (void *)"Count failed: %s\n", error.message);
            count = 0;
        }
        else
        {
            DBG_PRINT (DBG_DB, DBG_INFO, (void *)"0x%016llX documents counted.\n", count);
        }

#ifdef   _UNIT_TEST_
        {
            char  title[128];
            snprintf(title, 128, "blk_num(0x%016llX), tx_cnt(%llu)", blk_num, count);
        }
#endif

        bson_destroy (&query);
    } while (0);

    return ((uint32_t)count);
}

DB_RESULT_E mongodb_select_hash_f_blk_txs_w_dk(uint64_t db_key, uint8_t *p_tx_hash)
{
    MONGODB_INST_MGR_T  *p_mgr  = (MONGODB_INST_MGR_T*)db_get_db_inst_mgr();
    MONGODB_INST_T      *p_inst = NULL;
    DB_RESULT_E          ret    = DB_RESULT_SUCCESS;

    DBG_PRINT(DBG_CLI, DBG_TRACE, (void *)"%s\n", __FUNCTION__);

    p_inst = p_mgr->p_inst;

    if (NULL == p_inst)
    {
        DBG_PRINT (DBG_DB, DBG_ERROR, (void *)"Mongodb Instance getting fail.(all instance busy)\n");

        return (DB_RESULT_INSTANCE_GET_FAILURE);
    }

    do
    {
        bson_t *p_filter = BCON_NEW (DB_DB_KEY_STR, BCON_INT64 (db_key));
        bson_t *p_opts = BCON_NEW (
            "projection", "{",
                DB_SC_HASH_STR, BCON_BOOL (true),
                "_id", BCON_BOOL (false),
            "}");

        const bson_t *p_doc;
        bson_iter_t  iter;
        mongoc_cursor_t *p_cursor = mongoc_collection_find_with_opts (p_inst->p_blk_txs, p_filter, p_opts, NULL);

        if (mongoc_cursor_next (p_cursor, &p_doc) && bson_iter_init (&iter, p_doc) && bson_iter_next (&iter))
        {
            uint32_t    len    = 0;
            const char  *p_sc_hash = bson_iter_utf8 (&iter, &len);

            if (len != HASH_SIZE)
            {
                DBG_PRINT (DBG_DB, DBG_ERROR, (void *)"TXS sc_hash find fail.(db_key:%llu, len:%d, p_sc_hash:%s)\n", db_key, len, p_sc_hash);

                ret  = DB_RESULT_FAILURE;
            }
            else
            {
                MEMCPY_M(p_tx_hash, p_sc_hash, HASH_SIZE);
            }
        }

        mongoc_cursor_destroy (p_cursor);
        bson_destroy (p_filter);
        bson_destroy (p_opts);
    } while(0);

    return (ret);
}

uint64_t mongodb_select_db_key_f_blk_txs_w_bn(uint64_t blk_num, bool min_v)
{
    MONGODB_INST_MGR_T  *p_mgr    = (MONGODB_INST_MGR_T*)db_get_db_inst_mgr();
    MONGODB_INST_T      *p_inst   = NULL;
    uint64_t             db_key = 0;

    DBG_PRINT(DBG_CLI, DBG_TRACE, (void *)"%s\n", __FUNCTION__);

    p_inst = p_mgr->p_inst;

    if (NULL == p_inst)
    {
        DBG_PRINT (DBG_DB, DBG_ERROR, (void *)"Mongodb Instance getting fail.(all instance busy)\n");
        return (0);
    }

    do
    {
        bson_t *p_filter = BCON_NEW ("BlockNumber", BCON_INT64 (blk_num));
        bson_t *p_opts;
        mongoc_cursor_t  *p_cursor;
        const bson_t  *p_doc;
        bson_iter_t   iter;
        int32_t order;

        if (min_v) // First DB Key
        {
            order = MONGODB_ASCENDING_ORDER;
        }
        else // Last DB Key
        {
            order = MONGODB_DESCENDING_ORDER;
        }

        p_opts = BCON_NEW (
            "projection", "{",
                DB_DB_KEY_STR, BCON_BOOL (true),
                "_id", BCON_BOOL (false),
            "}",
            "limit", BCON_INT64(1),
            "sort", "{",
                "db_key", BCON_INT32(order),
            "}"
            );

        p_cursor = mongoc_collection_find_with_opts (p_inst->p_blk_txs, p_filter, p_opts, NULL);

        if (mongoc_cursor_next (p_cursor, &p_doc) && bson_iter_init (&iter, p_doc) && bson_iter_next (&iter))
        {
            db_key = bson_iter_int64 (&iter);
        }

        mongoc_cursor_destroy (p_cursor);
        bson_destroy (p_opts);
        bson_destroy (p_filter);
    } while(0);

    return (db_key);
}

DB_RESULT_E mongodb_select_blk_f_blk_contents_w_bn(uint64_t blk_num, CONS_LIGHT_BLK_T *p_light_blk)
{
    MONGODB_INST_MGR_T  *p_mgr  = (MONGODB_INST_MGR_T*)db_get_db_inst_mgr();
    MONGODB_INST_T      *p_inst = NULL;

    DBG_PRINT(DBG_CLI, DBG_TRACE, (void *)"%s\n", __FUNCTION__);

    p_inst = p_mgr->p_inst;

    if (NULL == (p_inst))
    {
        DBG_PRINT (DBG_DB, DBG_ERROR, (void *)"Mongodb Instance getting fail.(all instance busy)\n");

        return (DB_RESULT_INSTANCE_GET_FAILURE);
    }

    do
    {
        bson_t *p_filter = BCON_NEW (DB_BLK_NUM_STR, BCON_INT64 (blk_num));
        bson_t *p_opts   = BCON_NEW (
            "projection", "{",
                DB_P2P_ADDR_STR, BCON_BOOL (true),
                DB_BGT_STR, BCON_BOOL (true),
                DB_PBH_STR, BCON_BOOL (true),
                DB_TX_CNT_STR, BCON_BOOL (true),
                DB_BLK_HASH_STR, BCON_BOOL (true),
                DB_SIG_STR,  BCON_BOOL (true),
                DB_PUBKEY_STR,  BCON_BOOL (true),
                "_id",   BCON_BOOL (false),
            "}"
            );

        mongoc_cursor_t *p_cursor = mongoc_collection_find_with_opts (p_inst->p_blk_contents, p_filter, p_opts, NULL);

        const bson_t  *p_doc;
        bson_iter_t   iter;

        if (mongoc_cursor_next (p_cursor, &p_doc) && bson_iter_init (&iter, p_doc))
        {
            p_light_blk->blk_num = blk_num;
            
            while (bson_iter_next(&iter))
            {
                const char *key = bson_iter_key (&iter);

                if (!STRCMP_M(key, DB_P2P_ADDR_STR))
                {
                    p_light_blk->p2p_addr = bson_iter_int64(&iter);
                }
                else if (!STRCMP_M(key, DB_BGT_STR))
                {
                    p_light_blk->bgt = bson_iter_int64(&iter);
                }
                else if (!STRCMP_M(key, DB_PBH_STR))
                {
                    MEMCPY_M(p_light_blk->pbh, bson_iter_utf8(&iter, NULL), HASH_SIZE);
                }
                else if (!STRCMP_M(key, DB_TX_CNT_STR))
                {
                    p_light_blk->tx_cnt = bson_iter_int32(&iter);
                }
                else if (!STRCMP_M(key, DB_BLK_HASH_STR))
                {
                    MEMCPY_M(p_light_blk->blk_hash, bson_iter_utf8(&iter, NULL), HASH_SIZE);
                }
                else if (!STRCMP_M(key, DB_SIG_STR))
                {
                    MEMCPY_M(p_light_blk->sig, bson_iter_utf8(&iter, NULL), SIG_SIZE);
                }
                else if (!STRCMP_M(key, DB_SIG_PUBKEY_STR))
                {
                    MEMCPY_M(p_light_blk->sig_pubkey, bson_iter_utf8(&iter, NULL), COMP_PUBKEY_SIZE);
                }
                else
                {
                    DBG_PRINT (DBG_DB, DBG_ERROR, (void *)"Unknown type key: %s\n", key);
                }
            }
        }

        mongoc_cursor_destroy (p_cursor);
        bson_destroy (p_opts);
        bson_destroy (p_filter);
    } while(0);

    return DB_RESULT_SUCCESS;
}

DB_RESULT_E mongodb_select_blk_f_blk_prv_contents_w_bn(uint64_t blk_num, CONS_LIGHT_BLK_T *p_light_blk)
{
    MONGODB_INST_MGR_T  *p_mgr  = (MONGODB_INST_MGR_T*)db_get_db_inst_mgr();
    MONGODB_INST_T      *p_inst = NULL;

    DBG_PRINT(DBG_CLI, DBG_TRACE, (void *)"%s\n", __FUNCTION__);

    p_inst = p_mgr->p_inst;

    if (NULL == (p_inst))
    {
        DBG_PRINT (DBG_DB, DBG_ERROR, (void *)"Mongodb Instance getting fail.(all instance busy)\n");

        return (DB_RESULT_INSTANCE_GET_FAILURE);
    }

    do
    {
        bson_t *p_filter = BCON_NEW (DB_BLK_NUM_STR, BCON_INT64 (blk_num));
        bson_t *p_opts   = BCON_NEW (
            "projection", "{",
                DB_P2P_ADDR_STR, BCON_BOOL (true),
                DB_BGT_STR, BCON_BOOL (true),
                DB_PBH_STR, BCON_BOOL (true),
                DB_TX_CNT_STR, BCON_BOOL (true),
                DB_BLK_HASH_STR, BCON_BOOL (true),
                DB_SIG_STR, BCON_BOOL (true),
                DB_SIG_PUBKEY_STR, BCON_BOOL (true),
                "_id", BCON_BOOL (false),
            "}"
            );

        mongoc_cursor_t  *p_cursor = mongoc_collection_find_with_opts (p_inst->p_blk_prv_contents, p_filter, p_opts, NULL);

        const bson_t  *p_doc;
        bson_iter_t   iter;

        if (mongoc_cursor_next (p_cursor, &p_doc) && bson_iter_init (&iter, p_doc))
        {
            p_light_blk->blk_num = blk_num;
            
            while (bson_iter_next(&iter))
            {
                const char *key = bson_iter_key (&iter);

                if (!STRCMP_M(key, DB_P2P_ADDR_STR))
                {
                    p_light_blk->p2p_addr = bson_iter_int64(&iter);
                }
                else if (!STRCMP_M(key, DB_BGT_STR))
                {
                    p_light_blk->bgt = bson_iter_int64(&iter);
                }
                else if (!STRCMP_M(key, DB_PBH_STR))
                {
                    MEMCPY_M(p_light_blk->pbh, bson_iter_utf8(&iter, NULL), HASH_SIZE);
                }
                else if (!STRCMP_M(key, DB_TX_CNT_STR))
                {
                    p_light_blk->tx_cnt = bson_iter_int32(&iter);
                }
                else if (!STRCMP_M(key, DB_BLK_HASH_STR))
                {
                    MEMCPY_M(p_light_blk->blk_hash, bson_iter_utf8(&iter, NULL), HASH_SIZE);
                }
                else if (!STRCMP_M(key, DB_SIG_STR))
                {
                    MEMCPY_M(p_light_blk->sig, bson_iter_utf8(&iter, NULL), SIG_SIZE);
                }
                else if (!STRCMP_M(key, DB_SIG_PUBKEY_STR))
                {
                    MEMCPY_M(p_light_blk->sig_pubkey, bson_iter_utf8(&iter, NULL), COMP_PUBKEY_SIZE);
                }
                else
                {
                    DBG_PRINT (DBG_DB, DBG_ERROR, (void *)"Unknown type key: %s\n", key);
                }
            }
        }

        mongoc_cursor_destroy (p_cursor);
        bson_destroy (p_opts);
        bson_destroy (p_filter);
    } while(0);

    return DB_RESULT_SUCCESS;
}

DB_RESULT_E mongodb_select_hash_f_blk_contents_w_bn(uint64_t blk_num, uint8_t *p_blk_hash)
{
    MONGODB_INST_MGR_T  *p_mgr  = (MONGODB_INST_MGR_T*)db_get_db_inst_mgr();
    MONGODB_INST_T      *p_inst = NULL;
    DB_RESULT_E          ret  = DB_RESULT_SUCCESS;

    DBG_PRINT(DBG_CLI, DBG_TRACE, (void *)"%s\n", __FUNCTION__);

    p_inst = p_mgr->p_inst;

    if (NULL == (p_inst))
    {
        DBG_PRINT (DBG_DB, DBG_ERROR, (void *)"Mongodb Instance getting fail.(all instance busy)\n");

        return (DB_RESULT_INSTANCE_GET_FAILURE);
    }

    do
    {
        bson_t *p_filter = BCON_NEW (DB_BLK_NUM_STR, BCON_INT64 (blk_num));
        bson_t *p_opts   = BCON_NEW (
            "projection", "{",
                //DB_SUBNET_ID_STR, BCON_BOOL (true),
                //DB_BLK_NUM_STR, BCON_BOOL (true),
                //DB_SIG_TYPE_STR, BCON_BOOL (true),
                //DB_P2P_ADDR_STR, BCON_BOOL (true),
                //DB_BGT_STR, BCON_BOOL (true),
                //DB_PBH_STR, BCON_BOOL (true),
                //DB_TX_CNT_STR, BCON_BOOL (true),
                DB_BLK_HASH_STR, BCON_BOOL (true),
                //DB_SIG_STR,  BCON_BOOL (true),
                //DB_SIG_PUBKEY_STR, BCON_BOOL (true),
                "_id",   BCON_BOOL (false),
            "}"
            );

        mongoc_cursor_t *p_cursor = mongoc_collection_find_with_opts (p_inst->p_blk_contents, p_filter, p_opts, NULL);

        const bson_t  *p_doc;
        bson_iter_t   iter;

        if (mongoc_cursor_next (p_cursor, &p_doc) && bson_iter_init (&iter, p_doc))
        {
            while (bson_iter_next(&iter))
            {
                const char *key = bson_iter_key (&iter);
                uint32_t    len  = 0;

                if (!STRCMP_M(key, DB_BLK_HASH_STR))
                {
                    const char *p_hash  = bson_iter_utf8 (&iter, &len);
                    
                    if (len != HASH_SIZE)
                    {
                        DBG_PRINT (DBG_DB, DBG_ERROR, (void *)"blk_num find fail.(key:%s, blk_num:%llu, len:%d, %s)\n", key, blk_num, len, p_hash);

                        ret = DB_RESULT_FAILURE;
                    }
                    else
                    {
                        MEMCPY_M(p_blk_hash, p_hash, HASH_SIZE);
                    }
                    
                    break;
                }
            }
        }

        mongoc_cursor_destroy (p_cursor);
        bson_destroy (p_opts);
        bson_destroy (p_filter);
    } while(0);

    return (ret);
}

uint64_t mongodb_select_last_bn_f_blk_contents(void)
{
    MONGODB_INST_MGR_T *p_mgr  = (MONGODB_INST_MGR_T*)db_get_db_inst_mgr();
    MONGODB_INST_T     *p_inst = NULL;
    uint64_t            blk_num = 0;

    DBG_PRINT(DBG_CLI, DBG_TRACE, (void *)"%s\n", __FUNCTION__);

    p_inst = p_mgr->p_inst;

    if (NULL == (p_inst))
    {
        DBG_PRINT (DBG_DB, DBG_ERROR, (void *)"Mongodb Instance getting fail.(all instance busy)\n");

        return (0);
    }

    
    do
    {
        bson_t filter;
        bson_t *p_opts   = BCON_NEW (
            "projection", "{",
                //DB_SUBNET_ID_STR, BCON_BOOL (true),
                DB_BLK_NUM_STR, BCON_BOOL (true),
                //DB_P2P_ADDR_STR, BCON_BOOL (true),
                //DB_BGT_STR, BCON_BOOL (true),
                //DB_PBH_STR, BCON_BOOL (true),
                //DB_TX_CNT_STR, BCON_BOOL (true),
                //DB_BLK_HASH_STR, BCON_BOOL (true),
                //DB_SIG_STR,  BCON_BOOL (true),
                //DB_SIG_PUBKEY_STR, BCON_BOOL (true),
            "_id",   BCON_BOOL (false),
            "}",
            "limit", BCON_INT64(1),
            "sort", "{", 
                "BlockNumber", BCON_INT32(MONGODB_DESCENDING_ORDER),
            "}"
            );

        bson_init(&filter);
        
        mongoc_cursor_t *p_cursor = mongoc_collection_find_with_opts (p_inst->p_blk_contents, &filter, p_opts, NULL);

        const bson_t  *p_doc;
        bson_iter_t   iter;

        if (mongoc_cursor_next (p_cursor, &p_doc) && bson_iter_init (&iter, p_doc))
        {
            while (bson_iter_next(&iter))
            {
                const char *key = bson_iter_key (&iter);

                if (!STRCMP_M(key, DB_BLK_NUM_STR))
                {
                    blk_num  = bson_iter_int64 (&iter);
                    break;
                }

            }
        }

        mongoc_cursor_destroy (p_cursor);
        bson_destroy (p_opts);
        bson_destroy (&filter);
    } while(0);

    return (blk_num);
}

// EOF: db_mongodb.cpp
