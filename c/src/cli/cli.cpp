/**
    @file cli.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

CLI_CNTX_T g_cli_cntx;

static void cli_cntx_init(void)
{
    MEMSET_M(&g_cli_cntx, 0x00, sizeof(CLI_CNTX_T));

    json_cli_udpate(&g_cli_cntx);
}

void cli_init(void)
{
    cli_cntx_init();
}

CLI_CNTX_T *cli_get_cntx(void)
{
    return(&g_cli_cntx);
}

/////////////////////////////////////////////
static char *cli_log_file_path(void)
{
    char *p_file_path = (char *)CLI_LOG_FILE_PATH;

    DBG_PRINT (DBG_APP, DBG_NONE, (void *)"CLI_LOG_FILE_PATH : %s\n", p_file_path);

    return (p_file_path);
}

static char *cli_log_path(void)
{
    char *p_path = (char *)CLI_LOG_PATH;

    DBG_PRINT (DBG_APP, DBG_NONE, (void *)"CLI_LOG_PATH : %s\n", p_path);

    return (p_path);
}

//
static char *cli_get_last_log(FILE *fp)
{
    if(util_exists_file(cli_log_file_path()) == SUCCESS_)
    {
        FILE *cli_fp;
        char *p_last_log;
        uint32_t last_log_len;

        p_last_log = (char *)MALLOC_M(1024);
        
        cli_fp = fopen(cli_log_file_path(), "r");
        
        while(!feof(cli_fp))
        {
            (void)util_fgets(p_last_log, 1024, cli_fp);
        }
        
        fclose (cli_fp);

        last_log_len = STRLEN_M(p_last_log);

        DBG_FD_PRINT(fp, DBG_CLI, DBG_NONE, (void*)"last_log (%s) / last_log_len (%d)\n", p_last_log, last_log_len);

        if (last_log_len)
        {
            p_last_log[last_log_len-1] = '\0';

            return (p_last_log);
        }
        else
        {
            DBG_FD_PRINT(fp, DBG_CLI, DBG_ERROR, (void*)"last_log_len is equal to ZERO\n");
            FREE_M(p_last_log);
        }
    }
    else
    {
        DBG_FD_PRINT(fp, DBG_CLI, DBG_ERROR, (void*)"last_log : NOT founded\n");
    }

    return (NULL);
}

static void cli_save_log(FILE *fp, char *p_buf, uint32_t buf_len)
{
    if (buf_len && (STRSTR_M(p_buf, "!") != NULL))
    {
        DBG_FD_PRINT(fp, DBG_CLI, DBG_NONE, (void*)"ERROR : save_log (%s)\n", p_buf);
    }
    else
    {
        if (util_exists_dir(cli_log_path()) == ERROR_)
        {
            util_create_dir(cli_log_path());
        }

        if(util_exists_file(cli_log_file_path()) == ERROR_)
        {
            util_file_w(cli_log_file_path(), NULL, 0);
            
            util_file_a((char *)cli_log_file_path(), (uint8_t *)p_buf, buf_len);
            util_file_a((char *)cli_log_file_path(), (uint8_t *)"\n", 1);
        }
        else
        {
            char *p_last_log;
            p_last_log = cli_get_last_log(fp);

            if (p_last_log)
            {
                DBG_FD_PRINT(fp, DBG_CLI, DBG_NONE, (void*)"p_last_log(%s) p_buf(%s)\n", p_last_log, p_buf);
                if (STRCMP_M(p_last_log, p_buf) == 0)
                {
                    DBG_FD_PRINT(fp, DBG_CLI, DBG_NONE, (void*)"It was previous command. (%s)\n", p_buf);
                }
                else
                {
                    util_file_a((char *)cli_log_file_path(), (uint8_t *)p_buf, buf_len);
                    util_file_a((char *)cli_log_file_path(), (uint8_t *)"\n", 1);
                }
                
                FREE_M(p_last_log);
            }
            else
            {
                DBG_FD_PRINT(fp, DBG_CLI, DBG_ERROR, (void*)"p_last_log NONE\n");
            }
        }
    }
}

void cli_get_log_history(FILE *fp)
{
    FILE *cli_fp;

    cli_fp = fopen(cli_log_file_path(),"r");

    if(cli_fp != NULL)
    {
    	char buf[255];
        uint32_t cnt = 1;
        
    	while( !feof( cli_fp ) )
        {
        	if (util_fgets( buf, sizeof(buf), cli_fp ) != NULL)
                
            //if(EOF!=fscanf(fp, "%s", buf));
        	DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO,(void*)" %3d %s", cnt++, buf );
        }
        
    	fclose(cli_fp);
    }
	else
    {
        // file open error.
        DBG_FD_PRINT(fp, DBG_CLI, DBG_ERROR, (void*)"The LOG file CAN NOT be opened.\n");
    }
}

void cli_exe_last_log(FILE *fp)
{
    char *p_last_log;
    p_last_log = cli_get_last_log(fp);
    
    if(p_last_log)
    {
        cli_strtok_and_run(fp, p_last_log);
        
        FREE_M(p_last_log);
    }
}

void cli_handler(FILE *fp, char *p_buf)
{
    uint32_t buf_len;

    get_current_rss_monitor(DBG_NONE, (char *)"1");

    buf_len = STRLEN_M(p_buf);
    
    while(p_buf[buf_len-1] == ' ')
    {
        p_buf[buf_len-1] = '\0';
    }

    cli_save_log(fp, p_buf, buf_len);

    cli_strtok_and_run(fp, p_buf);

    get_current_rss_monitor(DBG_NONE, (char *)"2");
}

// Terminal Shall
int32_t cli_terminal(void)
{
    bool exe_thread = true;
    int32_t task_ret = TASK_EXIT_NORMAL;
    
    char *p_buf = NULL;
    size_t buf_len = 0;
    int32_t input = 0;

    DBG_PRINT(DBG_CLI, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    while (exe_thread)
    {
        DBG_PRINT(DBG_CLI, DBG_CLEAR, (void *)"> ");
        input = getline(&p_buf, &buf_len, stdin);

        if ((input > 0) && (p_buf))
        {
            p_buf[input - 1] = '\0';
            if(input != 1)
            {
                //DBG_PRINT(DBG_CLI, DBG_INFO, (void *)"You typed: '%s'\n", p_buf);
                cli_handler(stdout, p_buf);
            }
        }

        usleep(10);
    }

    FREE_M(p_buf);

    return (task_ret);
}

#if (CLI_SERIAL_EMULATOR == ENABLED)
// Terminal Serial Emulator
void cli_send_to_serial(int32_t fd, char *p_data, int32_t data_size)
{
    write (fd, p_data, data_size);
}

int32_t cli_recv_from_serial(int32_t fd, char *p_data, int32_t data_size)
{
    int32_t rnum = -1;

    rnum = read (fd, p_data, data_size);
    
    return (rnum);
}

#define RUN_SOCAT_INSELF ENABLED // ENABLED DISABLED
int32_t cli_serial_emulator(void)
{
    DBG_PRINT(DBG_CLI, DBG_TRACE, (void *)"%s\n", __FUNCTION__);

    bool exe_thread = true;
    int32_t task_ret = TASK_EXIT_NORMAL;

    char rbuf[CLI_RBUF_MAX];
    int32_t rnum;
    CLI_CNTX_T *p_cli_cntx = cli_get_cntx();


#if (RUN_SOCAT_INSELF == ENABLED)
    if (util_exists_file(p_cli_cntx->cli_tty_0_path) != SUCCESS_)
    {
        char socat_tty[CLI_PATH_MAX];
        uint32_t socat_tty_len = 0;

        STRCPY_M(&socat_tty[socat_tty_len], "gnome-terminal -e 'socat -d -d PTY,raw,echo=0,link=");
        socat_tty_len = STRLEN_M(socat_tty);
        
        STRCPY_M(&socat_tty[socat_tty_len], p_cli_cntx->cli_tty_0_path);
        socat_tty_len = STRLEN_M(socat_tty);
        
        STRCPY_M(&socat_tty[socat_tty_len], " PTY,raw,echo=0,link=");
        socat_tty_len = STRLEN_M(socat_tty);
        
        STRCPY_M(&socat_tty[socat_tty_len], p_cli_cntx->cli_tty_1_path);
        socat_tty_len = STRLEN_M(socat_tty);

        STRCPY_M(&socat_tty[socat_tty_len],"'");
        socat_tty_len = STRLEN_M(socat_tty);

        DBG_PRINT(DBG_CLI, DBG_INFO, (void *)"%s\n", socat_tty);
        
        system(socat_tty);
        //system("gnome-terminal -e 'socat -d -d PTY,raw,echo=0,link=/home/fas/dev/ttyV0 PTY,raw,echo=0,link=/home/fas/dev/ttyV1'");
        sleep(2);
    }
    else
    {
        DBG_PRINT(DBG_CLI, DBG_INFO, (void *)"ttyV0 is already exists.\n");
    }
#endif // RUN_SOCAT_INSELF

    int32_t fd = open (p_cli_cntx->cli_tty_0_path, O_RDWR | O_NOCTTY | O_SYNC);
    if (fd < 0)
    {
        DBG_PRINT(DBG_CLI, DBG_ERROR, (void *)"error %d opening %s: %s", errno, p_cli_cntx->cli_tty_0_path, strerror (errno));

        task_ret = errno;
        return (task_ret);
    }

    FILE *fp_input = fopen(p_cli_cntx->cli_tty_0_path, "r");
    FILE *fp_output = fopen(p_cli_cntx->cli_tty_0_path, "w");

    DBG_PRINT(DBG_CLI, DBG_INFO, (void *)"%s FD(%d)\n", p_cli_cntx->cli_tty_0_path, fd);
    
    //cli_send_to_serial (fd, (char *)"hello!\r\n", 8); 
    //DBG_FD_PRINT (fp_output, DBG_CLI, DBG_INFO, (void *)"Hello!\r\n");

    while (exe_thread)
    {
        if (util_exists_file(p_cli_cntx->cli_tty_0_path) != SUCCESS_)
        {
            DBG_PRINT(DBG_CLI, DBG_ERROR, (void *)"Error - %s FD(%d)\n", p_cli_cntx->cli_tty_0_path, fd);
            task_ret = TASK_EXIT_SERIAL_EMUL;
            break;
        }
        
        rnum = cli_recv_from_serial (fd, rbuf, sizeof(rbuf));
        
        if (rnum > 0)
        {
            if (rbuf[rnum-1] == '\r')
            {
                //cli_send_to_serial (fd, rbuf, rnum);
                DBG_FD_PRINT (fp_output, DBG_CLI, DBG_INFO, (void *)"%s", rbuf);
                rbuf[rnum-1] = '\n';

                p_cli_cntx->cli_rbuf[p_cli_cntx->cli_rbuf_len] = '\0';
                p_cli_cntx->cli_rbuf_len = 0;
            }
            else if (rbuf[rnum-1] == 0x08) // if '\b'
            {
                p_cli_cntx->cli_rbuf_len--;
            }
            else
            {
                MEMCPY_M(&p_cli_cntx->cli_rbuf[p_cli_cntx->cli_rbuf_len], rbuf, rnum);
                p_cli_cntx->cli_rbuf_len += rnum;
            }

            rbuf[rnum] = '\0';
            
            DBG_PRINT(DBG_CLI, DBG_NONE, (void *)"len(%d) %s\n", rnum, rbuf);
            //cli_send_to_serial (fd, rbuf, rnum);
            DBG_FD_PRINT (fp_output, DBG_CLI, DBG_INFO, (void *)"%s", rbuf);

            if (!p_cli_cntx->cli_rbuf_len && STRLEN_M(p_cli_cntx->cli_rbuf))
            {
                DBG_FD_PRINT (stdout, DBG_CLI, DBG_INFO, (void *)"%s(len:%d)\n", p_cli_cntx->cli_rbuf, STRLEN_M(p_cli_cntx->cli_rbuf));
                cli_handler(fp_output, p_cli_cntx->cli_rbuf);
            }
        }
        
        usleep (10);
    }

    if (fp_input)
    {
        fclose(fp_input);
    }

    if (fp_output)
    {
        fclose(fp_output);
    }
    
    return (task_ret);
}
#endif // CLI_SERIAL_EMULATOR


