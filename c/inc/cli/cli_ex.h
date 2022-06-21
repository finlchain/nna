/**
    @file cli_ex.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/


#ifndef __CLI_EX_H__
#define __CLI_EX_H__

#ifdef __cplusplus
extern "C"
{
#endif

typedef void (*cli_handler_ptr)(FILE *fp, uint32_t argc, const char **argv);

typedef struct {
    const char *p_cmd;
    const cli_handler_ptr cli_handler;
    const char *p_func_desc;
} cli_func_t;

extern void cli_parser(FILE *fp, uint32_t argc, const char **argv);
extern void cli_strtok_and_run(FILE *fp, char *p_buf);

#ifdef __cplusplus
}
#endif

#endif /* __CLI_EX_H__ */
