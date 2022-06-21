/**
    @file db_interface.cpp
    @date 2019/02/12
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

static DB_INSTANCE_T *db_inst_create_sub(DB_TYPE_E db_type, uint32_t mgr_cnt)
{
	DB_INSTANCE_T *p_new_inst = NULL;

    DBG_PRINT(DBG_CLI, DBG_TRACE, (void *)"%s\n", __FUNCTION__);

	p_new_inst  = (DB_INSTANCE_T*)MALLOC_M(sizeof(DB_INSTANCE_T));
	ASSERT_M(p_new_inst);

    //
	p_new_inst->db_type       = db_type;
	p_new_inst->mgr_cnt       = mgr_cnt;
	p_new_inst->b_use_ssl     = false;

	return (p_new_inst);
}

DB_INSTANCE_T *db_inst_create(DB_TYPE_E db_type)
{
    DB_INSTANCE_T *p_db_inst;

	p_db_inst = db_inst_create_sub(db_type, DB_INST_DEFAULT_CONN_CNT);

	ASSERT_M(p_db_inst);

    return (p_db_inst);
}

void db_inst_destroy_sub(DB_INSTANCE_T **pp_db_inst)
{
    DBG_PRINT(DBG_CLI, DBG_TRACE, (void *)"%s\n", __FUNCTION__);
    
    if (*pp_db_inst)
    {
    	DB_CONN_CLOSE(&((*pp_db_inst)->p_mgr));

    	FREE_M(*pp_db_inst);

        (*pp_db_inst) = NULL;
    }
}

void db_inst_destroy(void)
{
    DB_CNTX_T *p_db_cntx = db_get_cntx();

    db_inst_destroy_sub(&p_db_cntx->p_db_inst);
}

DB_RESULT_E db_set_conn_info(DB_INSTANCE_T *p_db_inst, char *p_db_host, uint16_t db_port, char *p_db_user, char *p_db_pw, char *p_db_name, char *p_db_sock, char *p_pw_path, char *p_seed_path)
{
    DB_RESULT_E db_ret = DB_RESULT_FAILURE;

    DBG_PRINT(DBG_CLI, DBG_TRACE, (void *)"%s\n", __FUNCTION__);

    if (p_db_inst)
    {
        db_ret = DB_CONN_INIT(&(p_db_inst->p_mgr), p_db_inst->mgr_cnt, p_db_host, db_port, p_db_user, p_db_pw, p_db_name, p_db_sock, p_pw_path, p_seed_path);
    }

	return (db_ret);
}

// db_interface test code
#ifdef   _UNIT_TEST_

typedef struct stcTestArgs {
	int    port;
	char   host[128];
	char   user[128];
	char   pass[128];
	char   dbname[128];
    char   sock[128];
} TestArgs_t;

void Usage(const char * prog )
{
	printf("\n\n");
	printf("Usage]---------------------------------------\n");
	printf("  %s -h IP -p PORT -U USERNAME -P PASSWORD -d DBNAME \n", prog);
	printf("\n\n");
}

int main(int argc, char* argv[])
{
	TestArgs_t    ta;
	DB_RESULT_E   db_ret = DB_RESULT_SUCCESS;
    DB_INSTANCE_T *p_db_inst = NULL;
	uint64_t      db_key = time(NULL);
	uint64_t      p2p_root_addr = 0x25347F0500110000;
	int32_t       tx_cnt = 5;
	uint64_t      bgt = 0;
	uint64_t      bct = 0;
	uint64_t      blk_num = 0;


	memset(&ta, 0x00, sizeof(TestArgs_t));
	printf("Unit test.\n");

	{
		int     opt = -1;


		while (-1 != (opt = getopt(argc, argv, "h:p:U:P:d:")))
		{
			switch (opt)
			{
				case 'h': { snprintf(ta.host,   128, optarg); } break;
				case 'p': { ta.port  = atoi(optarg);          } break;
				case 'U': { snprintf(ta.user,   128, optarg); } break;
				case 'P': { snprintf(ta.pass,   128, optarg); } break;
				case 'd': { snprintf(ta.dbname, 128, optarg); } break;
				default: break;
			}
		}

		if (!ta.host[0] || !ta.user[0] || !ta.pass[0] || !ta.dbname[0] || !ta.port)
		{
			Usage(argv[0]);
			return -1;
		}
	}

	p_db_inst = db_inst_create(DB_TYPE_MONGODB);
	db_ret = db_set_conn_info(p_db_inst, ta.host, ta.port, ta.user, ta.pass, ta.dbname, ta.sock, NULL, NULL);
	if (DB_RESULT_SUCCESS != db_ret)
	{
		return -2;
	}

	{ /** insert transaction contract **/
		char  sc_hash[] = "ppppppppp0qqqqqqqqq0rrrrrrrrr012";
		int   i      = 0;
		void  *arg   = NULL;
        bool  b_last = false;


		arg  = DB_INSERT_T_BLK_TX_START(0);
		for (i=0; i<tx_cnt; i++)
		{
            if ((i+1) == tx_cnt)
            {
                b_last = true;
            }
            
			sc_hash[i]  -= 'a' - 'A';
			db_ret  = DB_INSERT_T_BLK_TX_PROCESS(arg, b_last, 0, db_key+i, sc_hash);
			if (DB_RESULT_SUCCESS != db_ret)
			{
				return -2;
			}
		}
		DB_INSERT_T_BLK_TX_END(arg);
	}

	{ /** insert block contract **/
		CONS_LIGHT_BLK_T    lb;
		char                blk_hash[] = "xxxxxxxxx0yyyyyyyyy0zzzzzzzzz012";
		char                sig[SIG_SIZE];
		int                 i      = 0;


		memset(sig, 'g', SIG_SIZE);
		for (i = 0; i <SIG_SIZE; i++)
		{
			switch(i%7)
			{
				case 0: case 4:
				{
					sig[i]  = 'A' + i%26;
				} break;
				case 3: case 6:
				{
					sig[i]  = '0' + i%10;
				} break;
				default:
				{
					sig[i]  = 'a' + i%26;
				} break;
			}
		}

		lb.blk_num        = time(NULL) - 1554973373;
		lb.p2p_addr       = p2p_root_addr;
		lb.bgt = time(NULL);
		memcpy(lb.pbh, blk_hash, HASH_SIZE);
		lb.tx_cnt       = tx_cnt ;
		memcpy(lb.blk_hash, blk_hash, HASH_SIZE);
		memcpy(lb.sig, sig,SIG_SIZE);

		db_ret  = DB_INSERT_T_BLK_CONTENTS(&lb);

		bgt     = lb.bgt;
		blk_num      = lb.blk_num;
	}

	{ /** block update **/
		sleep(1);
		bct  = time(NULL);
		p_db_inst->update_status_t_info_w_bn(blk_num, 1, bct);
	}

	{ /** transaction update **/
		int  i = 0;

		for (i=0; i<5; i++)
		{
            p_db_inst->update_bn_t_tx_w_dk(db_key+i, blk_num);
		}
	}

	{ /** select lightBlock form block where blk_num = ? **/
		CONS_LIGHT_BLK_T sel_lb;

		memset(&sel_lb, 0x00, sizeof(CONS_LIGHT_BLK_T));
		if (DB_RESULT_SUCCESS == DB_SELECT_BLK_F_BLK_CONTENTS_W_BN(blk_num, &sel_lb))
		{
			printf("blk_num=%llu, p2p_addr=0x%016llX, bgt=%llu,"
					"pbh=%33s, tx_cnt=%u, blk_hash=%33s, sig=%32s\n",
					sel_lb.blk_num, sel_lb.p2p_addr, sel_lb.bgt,
					(char*)sel_lb.pbh, sel_lb.tx_cnt, (char*)sel_lb.blk_hash, (char*)sel_lb.sig
				  );
		}
		else
		{
			//
		}
	}

	{ /** select count(db_key) from txs where blk_num = ? **/
		printf("Select %llu count: %ld\n", blk_num,
				DB_SELECT_COUNT_F_BLK_TXS_W_BN(blk_num)
			  );
	}

	{ /** select block_hash from block where blk_num = ? **/
		char block_hash[128];

		memset(block_hash, 0x00, 128);
		if (DB_RESULT_SUCCESS == DB_SELECT_HASH_F_BLK_CONTENTS_W_BN(blk_num, block_hash))
		{
			printf("Select %llu block_hash: %s\n", blk_num, block_hash);
		}
		else
		{
			
		}
	}

	{ /** select tx_hash from txs where blk_num = ? **/
		char txHash[128];

		memset(txHash, 0x00, 128);
		if (DB_RESULT_SUCCESS == DB_SELECT_HASH_F_BLK_TXS_W_DK(db_key+2, txHash))
		{
			printf("Select %llu tx_hash: %s\n", blk_num, txHash);
		}
		else
		{
			//
		}
	}

	{ /** select db_key from txs limit 1 order by db_key desc  **/
		uint64_t ret_key = DB_SELECT_DB_KEY_F_BLK_TXS_W_BN(blk_num, false);
		printf("Last db_key = %llu\n", ret_key);
	}

	{ /** select blk_num from block limit 1 order by BlockNumber desc **/
		uint64_t ret_bn  = DB_SELECT_LAST_BN_F_BLK_CONTENTS();
		printf("Last blk_num = %llu\n", ret_bn);
	}

	db_inst_destroy_sub(&p_db_inst);

	return 0;
}
#endif


// EOF; db_interface.c
