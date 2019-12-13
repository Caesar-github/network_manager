#ifndef __DB_MONITOR_H
#define __DB_MONITOR_H

#ifdef __cplusplus
extern "C" {
#endif

struct NtpCfg {
    char *servers;
    char *zone;
    int automode;
    int time;
};

int database_get_ntp_time(void);
struct NtpCfg *database_get_ntp(void);
void *database_get_netconfig_json(char *service);
void dbserver_netconfig_set_connect(char *service, char *password, int *favorite, int *autoconnect);
void *database_get_netconfig(char *service);
int database_get_power(char *name, int *powers);
void database_init(void);

#ifdef __cplusplus
}
#endif

#endif
