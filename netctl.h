#ifndef __NETCTL_H
#define __NETCTL_H

#include <dbus/dbus.h>
#include <pthread.h>
#include <glib.h>
#include <gdbus.h>

//#define USE_DEBUG
#ifdef USE_DEBUG
#define DEBUG_LINE() printf("[%s:%s] line=%d\r\n",__FILE__, __func__, __LINE__)
#define DEBUG_ERR(fmt, args...) printf("\033[46;31m[%s:%d]\033[0m "#fmt" errno=%d, %m\r\n", __func__, __LINE__, ##args, errno, errno)
#define DEBUG_INFO(fmt, args...) printf("\033[33m[%s:%d]\033[0m "#fmt"\r\n", __func__, __LINE__, ##args)
#else
#define DEBUG_LINE()
#define DEBUG_ERR(fmt,...)
#define DEBUG_INFO(fmt,...)
#endif

typedef enum {
    TECH_PRO_CHANGED = 0,
    SERVICE_PRO_CHANAGED,
    SERVICE_CHANAGED,
    TECH_ADD,
    TECH_REMOVED,
} Massage_Type;

struct TechnologyStatus {
    char *Name;
    char *Type;
    int Powered;
    int Connected;
    int Tethering;
};

struct EthernetStatus {
    char *Method;
    char *Interface;
    char *Address;
    int MTU;
};

struct IPv4Status {
    char *Method;
    char *Address;
    char *Netmask;
    char *Gateway;
};

struct PropertiesStatus {
    char *service;
    char *Type;
    char *State;
    char *Name;
    char *Security;
    char *Nameservers;
    char *Nameservers_config;
    char *Timeservers;
    char *Timeservers_config;
    int Favorite;
    int Immutable;
    int AutoConnect;
    int Strength;
    struct EthernetStatus Ethernet;
    struct IPv4Status IPv4;
    struct IPv4Status IPv4_config;
};

struct NetworkService {
    char *service;
    char *password;
    int AutoConnect;
    int Favorite;
};

struct NetworkIP {
    char *interface;
    char *type;
    char *dns1;
    char *dns2;
    struct IPv4Status IPv4;
};

struct NetworkPower {
    char *type;
    int power;
};

struct NtpCfg {
    char *servers;
    char *zone;
    int automode;
    int time;
};

void synczone();
void syncntp(void);
void SyncAllNetconfig(void);
void SyncOneNetconfig(char *service);
void netctl_registered_call(void (*fun)(Massage_Type));
void netctl_unregistered_call(void);
void netctl_service_config_timeservers(char *service, char *ntp);
void netctl_service_config_nameservers(char *service, char *dns);
void netctl_service_config_remove(char *service);
void netctl_wifi_scan(void);
void netctl_service_config_ipv4(char *service, struct IPv4Status *config);//config->Method:dhcp,manual
void netctl_service_config_ipv4_dhcp(char *service);
void netctl_service_config_ipv4_manual(char *service, char *addr, char *netmask, char *gateway);
void netctl_free_service_list(void);
GList* netctl_get_service_list(void);
void netctl_service_connect(char *service, char *pwd);
void netctl_service_disconnect(char *service);
int netctl_get_cell_power(void);
int netctl_get_eth_power(void);
int netctl_get_wifi_power(void);
void netctl_set_power(char *name, int onoff);
void netctl_set_cell_power(int onoff);
void netctl_set_eth_power(int onoff);
void netctl_set_wifi_power(int onoff);
void netctl_init(void);
void netctl_deinit(void);
void netctl_clock_config_timeservers(char *ntp);
void netctl_clock_config_timeupdates(char *mode);//manual,auto
void netctl_clock_config_timezoneupdates(char *mode);
void netctl_clock_config_timezone(char *zone);
void netctl_run(void);
void netctl_getdns(char *interface, char **dns1, char **dns2);

#endif