#include "sys_utils.h"

#define CMD_BUF 256

int32_t Run_Shell_Read(const uint8_t *cmd, uint8_t *result) {
    ASSERT(cmd != NULL && result != NULL && CMD_BUF > (strlen(cmd) + strlen(" 2>&1")));
    if (strlen(result) > 0) result[0] = '\0';
    uint8_t result_temp[CMD_BUF];
    uint8_t run_cmd[CMD_BUF] = {0};
    FILE *  read_fd;
    sprintf(run_cmd, "%s 2>&1", cmd);
    if ((read_fd = popen(run_cmd, "r")) != NULL) {
        while (fgets(result_temp, CMD_BUF, read_fd) != NULL) {
            if (strlen(result) + strlen(result_temp) > CMD_BUF) break;
            strcat(result, result_temp);
        }
        if (result[strlen(result) - 1] == '\n') result[strlen(result) - 1] = '\0';
        pclose(read_fd);
        read_fd = NULL;
        return strlen(result);
    } else {
        Log_Err("%s-->%s() line %u: run \"%s\" fail.\n", __FILE__, __func__, __LINE__, run_cmd);
        return 0;
    }
}

void Assert(const uint8_t *file, const uint8_t *func, uint32_t line) {
    Log_Err("assert fail: %s-->%s() line %u\n", file, func, line);
    abort();
}

int8_t *Get_Cur_Path(void) { return get_current_dir_name(); }

#undef CMD_BUF
