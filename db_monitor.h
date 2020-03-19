#ifndef __DB_MONITOR_H
#define __DB_MONITOR_H

#ifdef __cplusplus
extern "C" {
#endif

struct NetworkConfig {
    char *hwaddr;
    char *method;
    char *ip;
    char *mask;
    char *gate;
    char *dns1;
    char *dns2;
};

int database_network_config(struct NetworkConfig *config);
struct NtpCfg *database_ntp_get(void);
void *database_networkservice_json_get(char *service);
void *database_networkip_json_get(char *interface);
void dbserver_netconfig_set_connect(char *service, char *password, int *favorite, int *autoconnect);
void *database_networkip_get(char *interface);
void *database_networkservice_get(char *service);
void *database_networkpower_json_get(char *type);
void *database_networkpower_get(char *type);
void database_init(void);
GHashTable *database_hash_network_ip_get(void);

#ifdef __cplusplus
}
#endif

#endif
