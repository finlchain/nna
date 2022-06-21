/**
    @file cli.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/


#ifndef __CLI_H__
#define __CLI_H__

#ifdef __cplusplus
extern "C"
{
#endif

#define CLI_SERIAL_EMULATOR DISABLED // ENABLED DISABLED

#define CLI_RBUF_MAX 100
#define CLI_PATH_MAX 400

#define CLI_CMD_BUF_MAX 255

typedef struct 
{
    char cli_rbuf[CLI_RBUF_MAX];
    int32_t cli_rbuf_len;
    
    char cli_tty_0_path[CLI_PATH_MAX];
    char cli_tty_1_path[CLI_PATH_MAX];
} CLI_CNTX_T;

extern void cli_init(void);
extern CLI_CNTX_T *cli_get_cntx(void);

// CLI Log
extern void cli_get_log_history(FILE *fp);
extern void cli_exe_last_log(FILE *fp);

//
extern void cli_handler(FILE *fp, char *p_buf);

// Terminal Shall
extern int32_t cli_terminal(void);

// Terminal Serial Emulator
#if (CLI_SERIAL_EMULATOR == ENABLED)
extern int32_t cli_serial_emulator(void);
#endif // CLI_SERIAL_EMULATOR

#ifdef __cplusplus
}
#endif

#endif /* __CLI_H__ */
