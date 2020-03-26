#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>
#include <ctype.h>
#include <inttypes.h>

#include <glib.h>
#include <gdbus.h>

#include <pthread.h>

#include "dbus_helpers.h"
#include "netctl.h"
#include "agent.h"
#include "db_monitor.h"
#include "network_func.h"

static pthread_t thread_id;
static int technology_init_flag = 0;
static int service_init_flag = 0;
static DBusConnection *connection = 0;

static GList* services_list = NULL;
static pthread_mutex_t service_mutex;
static pthread_mutex_t technology_mutex;
static GHashTable *technology_hash;
static void (*call)(Massage_Type) = NULL;
static gint ntptimeouttag = -1;

struct config_append {
    char **opts;
    int values;
};

struct config_clock {
    char *TimeUpdates;
    char *Timezone;
    char *TimezoneUpdates;
};

static char *ipv4[] = {
    "Method",
    "Address",
    "Netmask",
    "Gateway",
    NULL
};

struct move_service {
    char *service;
    char *target;
};

static struct config_clock* clockcfg = NULL;
static struct PropertiesStatus *get_status_by_service(char * service);

static gboolean time_ntp(gpointer arg)
{
    printf("%s\n", __func__);
    netctl_clock_config_timeservers("");
    return TRUE;
}

void synczone()
{
    struct NtpCfg *ntp = database_ntp_get();
    if ((ntp != NULL) && (clockcfg != NULL)) {
        char *Timezone = strstr(clockcfg->Timezone, "(null)/");
        if (Timezone)
            Timezone += 7;
        else
            Timezone = clockcfg->Timezone;
        printf("%s clockcfg->Timezone = %s, ntp->zone = %s\n", __func__, Timezone, ntp->zone);
        if (!g_str_equal(Timezone, ntp->zone)) {
            netctl_clock_config_timezoneupdates("manual");
            netctl_clock_config_timezone(ntp->zone);
        }
    }
}

void syncntp(void)
{
    struct NtpCfg *ntp = database_ntp_get();
    if (ntptimeouttag >= 0)
        g_source_remove(ntptimeouttag);
    ntptimeouttag = -1;
    if (ntp != NULL && ntp->automode) {
        netctl_clock_config_timeupdates("auto");
        netctl_clock_config_timeservers("");
        ntptimeouttag = g_timeout_add(ntp->time * 60000, time_ntp, NULL);
    } else {
        netctl_clock_config_timeupdates("manual");
    }
}

void syncnetconfig(struct PropertiesStatus *status)
{
    if (status) {
        if (g_str_equal(status->State, "online") || g_str_equal(status->State, "ready")) {
            struct NetworkIP *networkip = database_networkip_get(status->Ethernet.Interface);
            struct NtpCfg *ntp = database_ntp_get();
            if (ntp != NULL) {
                if (!g_str_equal(status->Timeservers_config, ntp->servers))
                    netctl_service_config_timeservers(status->service, ntp->servers);
            }

            if (networkip) {
                if ((networkip->IPv4.Method != NULL) && (status->IPv4_config.Method != NULL)) {
                    if (!g_str_equal(networkip->IPv4.Method, status->IPv4_config.Method)) {
                        if (g_str_equal(networkip->IPv4.Method, "manual") || g_str_equal(networkip->IPv4.Method, "dhcp"))
                            netctl_service_config_ipv4(status->service, &networkip->IPv4);
                    } else if (g_str_equal(networkip->IPv4.Method, "manual")) {
                        if (!g_str_equal(networkip->IPv4.Address, status->IPv4_config.Address) ||
                            !g_str_equal(networkip->IPv4.Gateway, status->IPv4_config.Gateway) ||
                            !g_str_equal(networkip->IPv4.Netmask, status->IPv4_config.Netmask)) {
                            netctl_service_config_ipv4(status->service, &networkip->IPv4);
                        }
                    }
                }

                if (g_str_equal(networkip->IPv4.Method, "dhcp")) {
                    if (!g_str_equal(status->Nameservers_config, ""))
                        netctl_service_config_nameservers(status->service, NULL);
                } else if (g_str_equal(networkip->IPv4.Method, "manual")) {
                    char *dns = NULL;
                    if ((networkip->dns1 != NULL) && !g_str_equal(networkip->dns1, "")) {
                        if ((networkip->dns2 != NULL) && !g_str_equal(networkip->dns2, ""))
                            dns = g_strdup_printf("%s %s", networkip->dns1, networkip->dns2);
                        else
                            dns = g_strdup(networkip->dns1);
                    } else {
                        if ((networkip->dns2 != NULL) && !g_str_equal(networkip->dns2, ""))
                            dns = g_strdup(networkip->dns2);
                    }

                    if (dns) {
                        if (!g_str_equal(dns, status->Nameservers_config))
                            netctl_service_config_nameservers(status->service, dns);
                        g_free(dns);
                    } else {
                        if (!g_str_equal(status->Nameservers_config, ""))
                            netctl_service_config_nameservers(status->service, NULL);
                    }
                }
            }
        }
    }
}

void SyncAllNetconfig(void)
{
    pthread_mutex_lock(&service_mutex);
    GList* list_tmp = g_list_first(services_list);
    while (list_tmp) {
        struct PropertiesStatus *status = (struct PropertiesStatus *)list_tmp->data;
        syncnetconfig(status);
        list_tmp = list_tmp->next;
    }

    pthread_mutex_unlock(&service_mutex);
}

void SyncOneNetconfig(char *service)
{
    pthread_mutex_lock(&service_mutex);
    struct PropertiesStatus *status = get_status_by_service(service);
    syncnetconfig(status);

    pthread_mutex_unlock(&service_mutex);
}

void updateclock(char *name, char *data)
{
    printf("%s %s %s\n", __func__, name, data);
    if (clockcfg == NULL) {
        clockcfg = malloc(sizeof(struct config_clock));
        clockcfg->TimeUpdates = g_strdup("");
        clockcfg->Timezone  = g_strdup("");
        clockcfg->TimezoneUpdates = g_strdup("");
    }

    if (strcmp(name, "TimeUpdates") == 0) {
        if (clockcfg->TimeUpdates)
            g_free(clockcfg->TimeUpdates);
        clockcfg->TimeUpdates = g_strdup(data);
    } else if (strcmp(name, "Timezone") == 0) {
        if (clockcfg->Timezone)
            g_free(clockcfg->Timezone);
        clockcfg->Timezone = g_strdup(data);
    } else if (strcmp(name, "TimezoneUpdates") == 0) {
        if (clockcfg->TimezoneUpdates)
            g_free(clockcfg->TimezoneUpdates);
        clockcfg->TimezoneUpdates = g_strdup(data);
    }
}

static char *get_path(char *full_path)
{
    char *path;

    path = strrchr(full_path, '/');
    if (path && *path != '\0')
        path++;
    else
        path = full_path;

    return path;
}

static void TechnologyPropertyChanged(const char *path, DBusMessageIter* iter)
{
    DBusMessageIter entry;
    char *strname;
    unsigned char bval;
    struct TechnologyStatus *status;

    pthread_mutex_lock(&technology_mutex);
    status = g_hash_table_lookup(technology_hash, get_path((char *)path));
    if (status) {
        dbus_message_iter_get_basic(iter, &strname);
        dbus_message_iter_next(iter);
        dbus_message_iter_recurse(iter, &entry);

        if (strcmp(strname, "Connected") == 0) {
            dbus_message_iter_get_basic(&entry, &bval);
            status->Connected = bval;
        } else if (strcmp(strname, "Powered") == 0) {
            dbus_message_iter_get_basic(&entry, &bval);
            status->Powered = bval;
        } else if (strcmp(strname, "Tethering") == 0) {
            dbus_message_iter_get_basic(&entry, &bval);
            status->Tethering = bval;
        }
    }
    pthread_mutex_unlock(&technology_mutex);
}

static void remove_technology(DBusMessageIter *iter)
{
    struct TechnologyStatus *status;
    char *path = NULL;

    if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_OBJECT_PATH)
        return;

    dbus_message_iter_get_basic(iter, &path);
    path = get_path(path);

    pthread_mutex_lock(&technology_mutex);
    status = (struct TechnologyStatus *)g_hash_table_lookup(technology_hash, path);

    if (status) {
        g_hash_table_remove(technology_hash, path);
        if (status->Name)
            g_free(status->Name);
        if (status->Type)
            g_free(status->Type);
        free(status);
    }
    pthread_mutex_unlock(&technology_mutex);
}

static void add_technology(DBusMessageIter *iter)
{
    char *path = NULL;
    DBusMessageIter entry;
    struct TechnologyStatus *status;

    if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_OBJECT_PATH)
        return;

    dbus_message_iter_get_basic(iter, &path);
    path = get_path(path);
    DEBUG_INFO("%s %s", __func__, path);

    dbus_message_iter_next(iter);

    if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY)
        return;

    pthread_mutex_lock(&technology_mutex);
    status = g_hash_table_lookup(technology_hash, path);
    if (status == NULL) {
        status = malloc(sizeof(struct TechnologyStatus));
        memset(status, 0, sizeof(struct TechnologyStatus));
        g_hash_table_replace(technology_hash, g_strdup(path), status);
    }

    if (dbus_message_iter_get_arg_type(iter) == DBUS_TYPE_ARRAY) {
        char *strname = NULL;
        dbus_message_iter_recurse(iter, &entry);

        while (dbus_message_iter_get_arg_type(&entry) == DBUS_TYPE_DICT_ENTRY) {
            DBusMessageIter subentry;
            char *strval = NULL;
            int val;
            dbus_message_iter_recurse(&entry, &subentry);
            dbus_message_iter_get_basic(&subentry, &strname);
            dbus_message_iter_next(&subentry);
            dbus_message_iter_recurse(&subentry, &subentry);

            if (strcmp(strname, "Name") == 0) {
                dbus_message_iter_get_basic(&subentry, &strval);
                DEBUG_INFO("%s = %s", strname, strval);
                if (status->Name)
                    g_free(status->Name);
                status->Name = g_strdup(strval);
            } else if (strcmp(strname, "Type") == 0) {
                dbus_message_iter_get_basic(&subentry, &strval);
                DEBUG_INFO("%s = %s", strname, strval);
                if (status->Type)
                    g_free(status->Type);
                status->Type = g_strdup(strval);
            } else if (strcmp(strname, "Powered") == 0) {
                dbus_message_iter_get_basic(&subentry, &val);
                DEBUG_INFO("%s = %d", strname, val);
                status->Powered = val;
            } else if (strcmp(strname, "Connected") == 0) {
                dbus_message_iter_get_basic(&subentry, &val);
                DEBUG_INFO("%s = %d", strname, val);
                status->Connected = val;
            } else if (strcmp(strname, "Tethering") == 0) {
                dbus_message_iter_get_basic(&subentry, &val);
                DEBUG_INFO("%s = %d", strname, val);
                status->Tethering = val;
            }
            dbus_message_iter_next(&entry);
        }
    }

    pthread_mutex_unlock(&technology_mutex);

    if (status->Type) {
        struct NetworkPower *networkpower = database_networkpower_get(status->Type);
        if (networkpower) {
            if (status->Powered != networkpower->power)
                netctl_set_power(status->Type, networkpower->power);
        }
    }
}

static void free_properties_status(struct PropertiesStatus *status)
{
    int i;

    if (status) {
        if (status->service)
            g_free(status->service);
        if (status->Type)
            g_free(status->Type);
        if (status->State)
            g_free(status->State);
        if (status->Security)
            g_free(status->Security);
        if (status->Nameservers)
            g_free(status->Nameservers);
        if (status->Nameservers_config)
            g_free(status->Nameservers_config);

        if (status->Timeservers)
            g_free(status->Timeservers);
        if (status->Timeservers_config)
            g_free(status->Timeservers_config);

        if (status->Ethernet.Method)
            g_free(status->Ethernet.Method);
        if (status->Ethernet.Interface)
            g_free(status->Ethernet.Interface);
        if (status->Ethernet.Address)
            g_free(status->Ethernet.Address);

        if (status->IPv4.Method)
            g_free(status->IPv4.Method);
        if (status->IPv4.Address)
            g_free(status->IPv4.Address);
        if (status->IPv4.Netmask)
            g_free(status->IPv4.Netmask);
        if (status->IPv4.Gateway)
            g_free(status->IPv4.Gateway);

        if (status->IPv4_config.Method)
            g_free(status->IPv4_config.Method);
        if (status->IPv4_config.Address)
            g_free(status->IPv4_config.Address);
        if (status->IPv4_config.Netmask)
            g_free(status->IPv4_config.Netmask);
        if (status->IPv4_config.Gateway)
            g_free(status->IPv4_config.Gateway);

        free(status);
    }
}

static void resolve_ethernet(DBusMessageIter* iter, struct EthernetStatus *Ethernet)
{
    DBusMessageIter entry;
    DBusMessageIter subentry;
    char *strname;
    char *strval;
    dbus_uint16_t u16val;

    dbus_message_iter_recurse(iter, &entry);

    while (dbus_message_iter_get_arg_type(&entry)) {
        dbus_message_iter_recurse(&entry, &subentry);
        dbus_message_iter_get_basic(&subentry, &strname);

        if (strcmp(strname, "Method") == 0) {
            dbus_message_iter_next(&subentry);
            dbus_message_iter_recurse(&subentry, &subentry);
            dbus_message_iter_get_basic(&subentry, &strval);
            if (Ethernet->Method)
                g_free(Ethernet->Method);
            Ethernet->Method = g_strdup(strval);
            DEBUG_INFO("%s = %s", strname, strval);
        } else if (strcmp(strname, "Address") == 0) {
            dbus_message_iter_next(&subentry);
            dbus_message_iter_recurse(&subentry, &subentry);
            dbus_message_iter_get_basic(&subentry, &strval);
            DEBUG_INFO("%s = %s", strname, strval);
            if (Ethernet->Address)
                g_free(Ethernet->Address);
            Ethernet->Address = g_strdup(strval);
        } else if (strcmp(strname, "Interface") == 0) {
            dbus_message_iter_next(&subentry);
            dbus_message_iter_recurse(&subentry, &subentry);
            dbus_message_iter_get_basic(&subentry, &strval);
            DEBUG_INFO("%s = %s", strname, strval);
            if (Ethernet->Interface)
                g_free(Ethernet->Interface);
            Ethernet->Interface = g_strdup(strval);
        } else if (strcmp(strname, "MTU") == 0) {
            dbus_message_iter_next(&subentry);
            dbus_message_iter_recurse(&subentry, &subentry);
            dbus_message_iter_get_basic(&subentry, &u16val);
            DEBUG_INFO("%s = %d", strname, u16val);
            Ethernet->MTU = u16val;
        }
        dbus_message_iter_next(&entry);
    }
}

static void resolve_ipv4(DBusMessageIter* iter, struct IPv4Status *IPv4)
{
    DBusMessageIter entry;
    DBusMessageIter subentry;
    char *strname;
    char *strval;

    dbus_message_iter_recurse(iter, &entry);

    while (dbus_message_iter_get_arg_type(&entry)) {
        dbus_message_iter_recurse(&entry, &subentry);
        dbus_message_iter_get_basic(&subentry, &strname);

        if (strcmp(strname, "Method") == 0) {
            dbus_message_iter_next(&subentry);
            dbus_message_iter_recurse(&subentry, &subentry);
            dbus_message_iter_get_basic(&subentry, &strval);
            if (IPv4->Method)
                g_free(IPv4->Method);
            IPv4->Method = g_strdup(strval);
            DEBUG_INFO("%s = %s", strname, strval);
        } else if (strcmp(strname, "Address") == 0) {
            dbus_message_iter_next(&subentry);
            dbus_message_iter_recurse(&subentry, &subentry);
            dbus_message_iter_get_basic(&subentry, &strval);
            DEBUG_INFO("%s = %s", strname, strval);
            if (IPv4->Address)
                g_free(IPv4->Address);
            IPv4->Address = g_strdup(strval);
        } else if (strcmp(strname, "Netmask") == 0) {
            dbus_message_iter_next(&subentry);
            dbus_message_iter_recurse(&subentry, &subentry);
            dbus_message_iter_get_basic(&subentry, &strval);
            DEBUG_INFO("%s = %s", strname, strval);
            if (IPv4->Netmask)
                g_free(IPv4->Netmask);
            IPv4->Netmask = g_strdup(strval);
        } else if (strcmp(strname, "Gateway") == 0) {
            dbus_message_iter_next(&subentry);
            dbus_message_iter_recurse(&subentry, &subentry);
            dbus_message_iter_get_basic(&subentry, &strval);
            DEBUG_INFO("%s = %s", strname, strval);
            if (IPv4->Gateway)
                g_free(IPv4->Gateway);
            IPv4->Gateway = g_strdup(strval);
        }
        dbus_message_iter_next(&entry);
    }
}

static void resolve_servers(DBusMessageIter *iter, char **servers)
{
    int i;
    char *strname = NULL;
    char *strval = NULL;
    DBusMessageIter subentry;
    if (*servers)
        g_free(*servers);
    *servers = g_strdup("");
    dbus_message_iter_recurse(iter, &subentry);
    for (i = 0; dbus_message_iter_get_arg_type(&subentry) == DBUS_TYPE_STRING; i++) {
        char *tmp = *servers;
        dbus_message_iter_get_basic(&subentry, &strval);
        DEBUG_INFO("%s = %s", strname, strval);
        if (i == 0)
            *servers = g_strdup_printf("%s", strval);
        else
            *servers = g_strdup_printf("%s %s", tmp, strval);
        g_free(tmp);
        dbus_message_iter_next(&subentry);
    }
}

static void resolve_clock(DBusMessageIter *iter)
{
    DBusMessageIter entry;

    while (dbus_message_iter_get_arg_type(iter) == DBUS_TYPE_DICT_ENTRY) {
        DBusMessageIter valentry;
        DBusMessageIter subentry;
        char *strname = NULL;
        char *strval = NULL;
        dbus_bool_t bval;

        dbus_message_iter_recurse(iter, &entry);
        dbus_message_iter_get_basic(&entry, &strname);
        dbus_message_iter_next(&entry);

        dbus_message_iter_recurse(&entry, &valentry);
        if (strcmp(strname, "TimeUpdates") == 0 ||
            strcmp(strname, "Timezone") == 0 ||
            strcmp(strname, "TimezoneUpdates") == 0) {
            dbus_message_iter_get_basic(&valentry, &strval);
            updateclock(strname, strval);
        }

        dbus_message_iter_next(iter);
    }
}

static void resolve_properties(DBusMessageIter *iter, struct PropertiesStatus *status)
{
    DBusMessageIter entry;
    int i;

    while (dbus_message_iter_get_arg_type(iter) == DBUS_TYPE_DICT_ENTRY) {
        DBusMessageIter valentry;
        DBusMessageIter subentry;
        char *strname = NULL;
        char *strval = NULL;
        dbus_uint16_t u16val;
        dbus_bool_t bval;

        dbus_message_iter_recurse(iter, &entry);
        dbus_message_iter_get_basic(&entry, &strname);
        dbus_message_iter_next(&entry);

        dbus_message_iter_recurse(&entry, &valentry);
        if (strcmp(strname, "Type") == 0) {
            dbus_message_iter_get_basic(&valentry, &strval);
            DEBUG_INFO("%s = %s", strname, strval);
            if (status->Type)
                g_free(status->Type);
            status->Type = g_strdup(strval);
        } else if (strcmp(strname, "Security") == 0) {
            resolve_servers(&valentry, &status->Security);
        } else if (strcmp(strname, "Nameservers") == 0) {
            resolve_servers(&valentry, &status->Nameservers);
        } else if (strcmp(strname, "Nameservers.Configuration") == 0) {
            resolve_servers(&valentry, &status->Nameservers_config);
        } else if (strcmp(strname, "Timeservers") == 0) {
            resolve_servers(&valentry, &status->Timeservers);
        } else if (strcmp(strname, "Timeservers.Configuration") == 0) {
            resolve_servers(&valentry, &status->Timeservers_config);
        } else if (strcmp(strname, "State") == 0) {
            dbus_message_iter_get_basic(&valentry, &strval);
            DEBUG_INFO("%s = %s", strname, strval);
            if (status->State)
                g_free(status->State);
            status->State = g_strdup(strval);
        } else if (strcmp(strname, "Favorite") == 0) {
            dbus_message_iter_get_basic(&valentry, &bval);
            DEBUG_INFO("%s = %d", strname, bval);
            status->Favorite = bval;
        } else if (strcmp(strname, "Immutable") == 0) {
            dbus_message_iter_get_basic(&valentry, &bval);
            DEBUG_INFO("%s = %d", strname, bval);
            status->Immutable = bval;
        } else if (strcmp(strname, "AutoConnect") == 0) {
            dbus_message_iter_get_basic(&valentry, &bval);
            DEBUG_INFO("%s = %d", strname, bval);
            status->AutoConnect = bval;
        } else if (strcmp(strname, "Name") == 0) {
            dbus_message_iter_get_basic(&valentry, &strval);
            DEBUG_INFO("%s = %s", strname, strval);
            if (status->Name)
                g_free(status->Name);
            status->Name = g_strdup(strval);
        } else if (strcmp(strname, "Ethernet") == 0) {
            resolve_ethernet(&valentry, &status->Ethernet);
        } else if (strcmp(strname, "IPv4") == 0) {
            resolve_ipv4(&valentry, &status->IPv4);
        } else if (strcmp(strname, "IPv4.Configuration") == 0) {
            resolve_ipv4(&valentry, &status->IPv4_config);
        }

        dbus_message_iter_next(iter);
    }
}

static struct PropertiesStatus *allocproertiesstatus(char *service)
{
    struct PropertiesStatus *status = malloc(sizeof(struct PropertiesStatus));
    memset(status, 0, sizeof(struct PropertiesStatus));
    status->service = g_strdup(service);

    status->IPv4.Method = g_strdup("");
    status->IPv4.Address = g_strdup("");
    status->IPv4.Netmask = g_strdup("");
    status->IPv4.Gateway = g_strdup("");
    status->IPv4_config.Method = g_strdup("");
    status->IPv4_config.Address = g_strdup("");
    status->IPv4_config.Netmask = g_strdup("");
    status->IPv4_config.Gateway = g_strdup("");

    return status;
}

static void services_added(DBusMessageIter *iter)
{
    DBusMessageIter array;
    char *path = NULL;
    GList *list = NULL;
    GList *list_old = NULL;
    int i = 0;

    while (dbus_message_iter_get_arg_type(iter) == DBUS_TYPE_STRUCT) {
        struct PropertiesStatus *status;
        dbus_message_iter_recurse(iter, &array);
        if (dbus_message_iter_get_arg_type(&array) !=
            DBUS_TYPE_OBJECT_PATH)
            return;

        dbus_message_iter_get_basic(&array, &path);
        dbus_message_iter_next(&array);

        dbus_message_iter_recurse(&array, &array);

        status = allocproertiesstatus(get_path(path));

        resolve_properties(&array, status);
        //dump_properties_status(status);

        DEBUG_INFO("%s name %s", __func__, status->Name);
        list = g_list_insert(list, status, i++);
        dbus_message_iter_next(iter);
    }

    pthread_mutex_lock(&service_mutex);

    list_old = g_list_first(services_list);
    while (list_old) {
        struct PropertiesStatus *status = (struct PropertiesStatus *)list_old->data;
        free_properties_status(status);
        list_old = list_old->next;
    }
    g_list_free(services_list);
    services_list = g_list_first(list);
    pthread_mutex_unlock(&service_mutex);
}

void services_remove(char *service)
{
    GList *list;

    pthread_mutex_lock(&service_mutex);
    list = g_list_first(services_list);
    while (list) {
        struct PropertiesStatus *status = (struct PropertiesStatus *)list->data;
        if (strcmp(status->service, service) == 0) {
            free_properties_status(status);
            list = g_list_delete_link(services_list, list);
            services_list = g_list_first(list);
            break;
        }
        list = list->next;
    }

    pthread_mutex_unlock(&service_mutex);
}

static struct PropertiesStatus *get_status_by_service(char * service)
{
    GList *list = g_list_first(services_list);
    while (list) {
        struct PropertiesStatus *status = (struct PropertiesStatus *)list->data;
        if (strcmp(status->service, service) == 0) {
            return status;
        }
        list = list->next;
    }

    return 0;
}

static struct PropertiesStatus *get_status_del_by_service(char * service)
{
    struct PropertiesStatus *status = 0;
    GList *list = g_list_first(services_list);
    while (list) {
        status = (struct PropertiesStatus *)list->data;
        if (strcmp(status->service, service) == 0) {
            list = g_list_delete_link(services_list, list);
            services_list = g_list_first(list);
            break;
        }
        list = list->next;
        status = 0;
    }

    return status;
}

static void ServicePropertyChanged(char *path, DBusMessageIter* iter)
{
    DBusMessageIter entry;
    char *strname;
    char *strval;
    unsigned char cval;
    struct PropertiesStatus *status;

    pthread_mutex_lock(&service_mutex);
    status = get_status_by_service(get_path(path));
    if (status) {
        dbus_message_iter_get_basic(iter, &strname);
        dbus_message_iter_next(iter);
        dbus_message_iter_recurse(iter, &entry);
        if (strcmp(strname, "State") == 0) {
            if (status->State)
                g_free(status->State);
            status->State = 0;
            if (dbus_message_iter_get_arg_type(&entry) == DBUS_TYPE_STRING) {
                dbus_message_iter_get_basic(&entry, &strval);
                DEBUG_INFO("%s = %s", strname, strval);
                status->State = g_strdup(strval);
            }
        } else if (strcmp(strname, "Strength") == 0) {
            dbus_message_iter_get_basic(&entry, &cval);
            DEBUG_INFO("%s = %d", strname, cval);
            status->Strength = cval;
        } else if (strcmp(strname, "Timeservers") == 0) {
            resolve_servers(&entry, &status->Timeservers);
        } else if (strcmp(strname, "Timeservers.Configuration") == 0) {
            resolve_servers(&entry, &status->Timeservers_config);
        } else if (strcmp(strname, "IPv4") == 0) {
            resolve_ipv4(&entry, &(status->IPv4));
        } else if (strcmp(strname, "IPv4.Configuration") == 0) {
            resolve_ipv4(&entry, &status->IPv4_config);
        } else if (strcmp(strname, "Domains") == 0) {
            dbus_message_iter_recurse(&entry, &entry);
        } else if (strcmp(strname, "Proxy") == 0) {
            dbus_message_iter_recurse(&entry, &entry);
        } else if (strcmp(strname, "Nameservers") == 0) {
            resolve_servers(&entry, &status->Nameservers);
        } else if (strcmp(strname, "Nameservers.Configuration") == 0) {
            resolve_servers(&entry, &status->Nameservers_config);
        } else if (strcmp(strname, "AutoConnect") == 0) {
            dbus_message_iter_get_basic(&entry, &cval);
            status->AutoConnect = cval;
        } else if (strcmp(strname, "Favorite") == 0) {
            dbus_message_iter_get_basic(&entry, &cval);
            status->Favorite = cval;
        }
    }
    pthread_mutex_unlock(&service_mutex);
    SyncOneNetconfig(get_path(path));
}

static void services_update(DBusMessageIter *iter)
{
    DBusMessageIter array;
    char *path = NULL;
    GList *list = NULL;
    GList *list_old = NULL;
    int i = 0;

    pthread_mutex_lock(&service_mutex);

    while (dbus_message_iter_get_arg_type(iter) == DBUS_TYPE_STRUCT) {
        struct PropertiesStatus *status;
        dbus_message_iter_recurse(iter, &array);
        if (dbus_message_iter_get_arg_type(&array) !=
            DBUS_TYPE_OBJECT_PATH)
            return;

        dbus_message_iter_get_basic(&array, &path);
        path = get_path(path);

        dbus_message_iter_next(&array);
        dbus_message_iter_recurse(&array, &array);


        status = get_status_del_by_service(path);//(struct PropertiesStatus *)g_hash_table_lookup(netinfo.service_hash, path);
        if (status == NULL)
            status = allocproertiesstatus(get_path(path));

        list = g_list_insert(list, status, i++);

        resolve_properties(&array, status);
        //dump_properties_status(status);

        dbus_message_iter_next(iter);
    }

    list_old = g_list_first(services_list);
    while (list_old) {
        struct PropertiesStatus *status = (struct PropertiesStatus *)list_old->data;
        free_properties_status(status);
        list_old = list_old->next;
    }
    g_list_free(services_list);
    services_list = g_list_first(list);
    pthread_mutex_unlock(&service_mutex);
}

static void ServicesChanged(DBusMessageIter *iter)
{
    DBusMessageIter array;
    char *path;

    if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY)
        return;
    dbus_message_iter_recurse(iter, &array);

    services_update(&array);
    dbus_message_iter_next(iter);
    if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY)
        goto out;

    dbus_message_iter_recurse(iter, &array);

    while (dbus_message_iter_get_arg_type(&array) ==
           DBUS_TYPE_OBJECT_PATH) {
        dbus_message_iter_get_basic(&array, &path);
        DEBUG_INFO("%s remove %s", __func__, path);
        services_remove(get_path(path));

        dbus_message_iter_next(&array);
    }
out:
    SyncAllNetconfig();
}

static int populate_service_hash(DBusMessageIter *iter, const char *error,
                                 void *user_data)
{
    DBusMessageIter array;
    char *path;

    if (error) {
        fprintf(stderr, "Error getting services: %s", error);
        return 0;
    }
    service_init_flag = 1;

    if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY)
        return 0;

    dbus_message_iter_recurse(iter, &array);

    services_added(&array);
    dbus_message_iter_next(iter);
    if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY)
        goto out;

    dbus_message_iter_recurse(iter, &array);

    while (dbus_message_iter_get_arg_type(&array) ==
           DBUS_TYPE_OBJECT_PATH) {
        dbus_message_iter_get_basic(&array, &path);
        DEBUG_INFO("%s remove %s", __func__, path);
        services_remove(get_path(path));

        dbus_message_iter_next(&array);
    }

out:
    SyncAllNetconfig();
    if (call)
        call(SERVICE_CHANAGED);
    return 0;
}

static int populate_technology_hash(DBusMessageIter *iter, const char *error,
                                    void *user_data)
{
    DBusMessageIter array;

    if (error) {
        fprintf(stderr, "Error getting technologies: %s", error);
        return 0;
    }

    technology_init_flag = 1;

    if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY)
        return 0;

    dbus_message_iter_recurse(iter, &array);

    while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_STRUCT) {
        DBusMessageIter entry;

        dbus_message_iter_recurse(&array, &entry);
        add_technology(&entry);
        dbus_message_iter_next(&array);
    }

    if (call)
        call(TECH_ADD);
    return 0;
}

static int populate_clock(DBusMessageIter *iter, const char *error,
                          void *user_data)
{
    DBusMessageIter entry;

    if (error) {
        fprintf(stderr, "Error get clock: %s\n", error);
        return 0;
    }

    if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY)
        return 0;

    dbus_message_iter_recurse(iter, &entry);
    resolve_clock(&entry);
    synczone();

    return 0;
}

static int populate_vpnconnection_hash(DBusMessageIter *iter, const char *error,
                                       void *user_data)
{
    DBusMessageIter array;

    if (error) {
        fprintf(stderr, "Error getting VPN connections: %s\n", error);
        return 0;
    }

    if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY)
        return 0;

    dbus_message_iter_recurse(iter, &array);

    //add_vpnconnections(&array);

    return 0;
}

static int populate_peer_hash(DBusMessageIter *iter,
                              const char *error, void *user_data)
{
    if (error) {
        fprintf(stderr, "Error getting peers: %s", error);
        return 0;
    }

    //update_peers(iter);
    return 0;
}

static gboolean time_cb(gpointer arg)
{
    if (connection == 0)
        return TRUE;

    if (technology_init_flag == 0) {
        __connmanctl_dbus_method_call(connection,
                                      CONNMAN_SERVICE, CONNMAN_PATH,
                                      "net.connman.Manager", "GetTechnologies",
                                      populate_technology_hash, NULL, NULL, NULL);
        return TRUE;
    }

    if (service_init_flag == 0) {
        __connmanctl_dbus_method_call(connection,
                                      CONNMAN_SERVICE, CONNMAN_PATH,
                                      "net.connman.Manager", "GetServices",
                                      populate_service_hash, NULL, NULL, NULL);
        return TRUE;
    }

    if ((technology_init_flag == 1) &&
        (service_init_flag == 1))
        return FALSE;

    return TRUE;
}

static DBusHandlerResult monitor_completions_changed(
    DBusConnection *connection,
    DBusMessage *message, void *user_data)
{
    bool *enabled = user_data;
    DBusMessageIter iter;
    DBusHandlerResult handled;

    handled = DBUS_HANDLER_RESULT_HANDLED;

    if (dbus_message_is_signal(message, "net.connman.Clock",
                               "PropertyChanged")) {
        const char * path = dbus_message_get_path(message);
        DBusMessageIter valentry;
        char *strname;
        printf("%s clock PropertyChanged\n", __func__);
        dbus_message_iter_init(message, &iter);

        dbus_message_iter_get_basic(&iter, &strname);
        dbus_message_iter_next(&iter);

        dbus_message_iter_recurse(&iter, &valentry);
        if (strcmp(strname, "TimeUpdates") == 0 ||
            strcmp(strname, "Timezone") == 0 ||
            strcmp(strname, "TimezoneUpdates") == 0) {
            char *strval;
            dbus_message_iter_get_basic(&valentry, &strval);
            updateclock(strname, strval);
        }

        return handled;
    }

    if (dbus_message_is_signal(message, "net.connman.Technology",
                               "PropertyChanged")) {
        const char * path = dbus_message_get_path(message);
        DEBUG_INFO("%s Technology PropertyChanged", __func__);
        dbus_message_iter_init(message, &iter);
        TechnologyPropertyChanged(path, &iter);
        if (call)
            call(TECH_PRO_CHANGED);
        return handled;
    }

    if (dbus_message_is_signal(message, "net.connman.Service",
                               "PropertyChanged")) {
        const char * path = dbus_message_get_path(message);
        DEBUG_INFO("%s Service PropertyChanged", __func__);
        dbus_message_iter_init(message, &iter);
        ServicePropertyChanged((char *)path, &iter);
        if (call)
            call(SERVICE_PRO_CHANAGED);
        return handled;
    }

    if (dbus_message_is_signal(message, "net.connman.Manager",
                               "ServicesChanged")) {
        DEBUG_INFO("%s ServicesChanged", __func__);
        dbus_message_iter_init(message, &iter);
        ServicesChanged(&iter);
        if (call)
            call(SERVICE_CHANAGED);
        return handled;
    }
    /*
        if (dbus_message_is_signal(message, "net.connman.vpn.Manager",
            "ConnectionAdded")) {
            DEBUG_INFO("%s ConnectionAdded", __func__);
            dbus_message_iter_init(message, &iter);
            vpnconnection_added(&iter);
            return handled;
        }

        if (dbus_message_is_signal(message, "net.connman.vpn.Manager",
            "ConnectionRemoved")) {
            DEBUG_INFO("%s ConnectionRemoved", __func__);
            dbus_message_iter_init(message, &iter);
            vpnconnection_removed(&iter);
            return handled;
        }

        if (dbus_message_is_signal(message, "net.connman.Manager",
            "PeersChanged")) {
            DEBUG_INFO("%s PeersChanged", __func__);
            dbus_message_iter_init(message, &iter);
            update_peers(&iter);
            return handled;
        }
    */
    if (dbus_message_is_signal(message, "net.connman.Manager",
                               "TechnologyAdded")) {
        DEBUG_INFO("%s TechnologyAdded", __func__);
        dbus_message_iter_init(message, &iter);
        add_technology(&iter);
        if (call)
            call(TECH_ADD);
        return handled;
    }

    if (dbus_message_is_signal(message, "net.connman.Manager",
                               "TechnologyRemoved")) {
        DEBUG_INFO("%s TechnologyRemoved", __func__);
        dbus_message_iter_init(message, &iter);
        remove_technology(&iter);
        if (call)
            call(TECH_REMOVED);
        return handled;
    }

    if (!g_strcmp0(dbus_message_get_interface(message),
                   "net.connman.Manager"))
        return handled;

    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static int agent_onoff(int onoff)
{
    switch (onoff) {
    case 0:
        __connmanctl_agent_unregister(connection);
        break;

    case 1:
        if (__connmanctl_agent_register(connection) == -EINPROGRESS)
            return -EINPROGRESS;
        break;

    default:
        return -EINVAL;
        break;
    }

    return 0;
}

static void __connmanctl_monitor_completions(DBusConnection *dbus_conn)
{
    DBusError err;

    if (!dbus_conn) {
        //g_hash_table_destroy(vpnconnection_hash);
        //g_hash_table_destroy(peer_hash);
        g_hash_table_destroy(technology_hash);

        dbus_bus_remove_match(connection,
                              "type='signal',interface='net.connman.Manager'", NULL);
        dbus_bus_remove_match(connection,
                              "type='signal',interface='net.connman.vpn.Manager'", NULL);
        dbus_connection_remove_filter(connection,
                                      monitor_completions_changed, NULL);
        return;
    }

    //vpnconnection_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
    //    g_free, NULL);

    //peer_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
    //    g_free, NULL);

    technology_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
                                            g_free, NULL);

    pthread_mutex_init(&service_mutex, NULL);
    pthread_mutex_init(&technology_mutex, NULL);

    service_init_flag = 0;
    technology_init_flag = 0;

    __connmanctl_dbus_method_call(connection,
                                  VPN_SERVICE, CONNMAN_PATH,
                                  "net.connman.vpn.Manager", "GetConnections",
                                  populate_vpnconnection_hash, NULL, NULL, NULL);

    __connmanctl_dbus_method_call(connection,
                                  CONNMAN_SERVICE, CONNMAN_PATH,
                                  "net.connman.Manager", "GetPeers",
                                  populate_peer_hash, NULL, NULL, NULL);

    __connmanctl_dbus_method_call(connection,
                                  CONNMAN_SERVICE, CONNMAN_PATH,
                                  "net.connman.Clock", "GetProperties",
                                  populate_clock, NULL, NULL, NULL);


    /*
        __connmanctl_dbus_method_call(connection,
            CONNMAN_SERVICE, CONNMAN_PATH,
            "net.connman.Manager", "GetServices",
            populate_service_hash, NULL, NULL, NULL);

        __connmanctl_dbus_method_call(connection,
            CONNMAN_SERVICE, CONNMAN_PATH,
            "net.connman.Manager", "GetTechnologies",
            populate_technology_hash, NULL, NULL, NULL);
    */
    dbus_connection_add_filter(connection,
                               monitor_completions_changed, NULL, NULL);

    dbus_error_init(&err);
    dbus_bus_add_match(connection,
                       "type='signal',interface='net.connman.Manager'", &err);

    if (dbus_error_is_set(&err)) {
        fprintf(stderr, "Error: %s\n", err.message);
        return;
    }

    dbus_bus_add_match(connection,
                       "type='signal',interface='net.connman.vpn.Manager'",
                       &err);

    if (dbus_error_is_set(&err))
        fprintf(stderr, "Error: %s\n", err.message);

    dbus_bus_add_match(connection,
                       "type='signal',interface='net.connman.Service'",
                       &err);

    if (dbus_error_is_set(&err))
        fprintf(stderr, "Error: %s\n", err.message);

    dbus_bus_add_match(connection,
                       "type='signal',interface='net.connman.Technology'",
                       &err);

    dbus_bus_add_match(connection,
                       "type='signal',interface='net.connman.Clock'",
                       &err);

    if (dbus_error_is_set(&err))
        fprintf(stderr, "Error: %s\n", err.message);

    agent_onoff(1);
}

static void *netctl_thread(void *arg)
{
    int err;
    DBusError dbus_err;
    GMainLoop *main_loop;

    __connmanctl_monitor_completions(connection);

    main_loop = g_main_loop_new(NULL, FALSE);
    g_timeout_add(100, time_cb, NULL);
    struct NtpCfg *ntp = database_ntp_get();
    if (ntp != NULL && ntp->automode) {
        netctl_clock_config_timeupdates("auto");
        ntptimeouttag = g_timeout_add(ntp->time * 60000, time_ntp, NULL);
    } else {
        ntptimeouttag = -1;
        netctl_clock_config_timeupdates("manual");
    }
    g_main_loop_run(main_loop);
    dbus_connection_unref(connection);
    if (main_loop)
        g_main_loop_unref(main_loop);
    return 0;
}

static int netctl_get_power(char *technology)
{
    struct TechnologyStatus *status;
    int powered = 0;

    pthread_mutex_lock(&technology_mutex);
    status = g_hash_table_lookup(technology_hash, technology);

    if (status)
        powered = status->Powered;
    pthread_mutex_unlock(&technology_mutex);

    return powered;
}

static void netctl_update_power(char *technology, int onoff)
{
    struct TechnologyStatus *status;

    pthread_mutex_lock(&technology_mutex);
    status = g_hash_table_lookup(technology_hash, technology);

    if (status)
        status->Powered = onoff;
    pthread_mutex_unlock(&technology_mutex);
}

static int config_return(DBusMessageIter *iter, const char *error,
                         void *user_data)
{
    char *service_name = user_data;

    if (error)
        fprintf(stderr, "Error %s: %s\n", service_name, error);

    g_free(user_data);

    return 0;
}

static int disconnect_return(DBusMessageIter *iter, const char *error,
                             void *user_data)
{
    char *path = user_data;

    if (!error) {
        char *str = strrchr(path, '/');
        str++;
        fprintf(stdout, "Disconnected %s\n", str);
    } else
        fprintf(stderr, "Error %s: %s\n", path, error);

    g_free(user_data);

    return 0;
}

static int connect_return(DBusMessageIter *iter, const char *error,
                          void *user_data)
{
    char *path = user_data;

    if (!error) {
        char *str = strrchr(path, '/');
        str++;
        fprintf(stdout, "Connected %s\n", str);
    } else
        fprintf(stderr, "Error %s: %s\n", path, error);

    g_free(user_data);

    return 0;
}

static void config_append_str(DBusMessageIter *iter, void *user_data)
{
    struct config_append *append = user_data;
    char **opts = append->opts;
    int i = 0;

    if (!opts)
        return;

    while (opts[i]) {
        dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING,
                                       &opts[i]);
        i++;
    }

    append->values = i;
}

static void config_append_ipv4(DBusMessageIter *iter,
                               void *user_data)
{
    struct config_append *append = user_data;
    char **opts = append->opts;
    int i = 0;

    if (!opts)
        return;

    while (opts[i] && ipv4[i]) {
        //printf("%s,%s\n", ipv4[i], opts[i]);
        __connmanctl_dbus_append_dict_entry(iter, ipv4[i],
                                            DBUS_TYPE_STRING, &opts[i]);
        i++;
    }

    append->values = i;
}

static int scan_return(DBusMessageIter *iter, const char *error,
                       void *user_data)
{
    char *path = user_data;

    if (error)
        fprintf(stderr, "Error %s: %s\n", path, error);

    g_free(user_data);

    return 0;
}

static int enable_return(DBusMessageIter *iter, const char *error,
                         void *user_data)
{
    char *tech = user_data;
    char *str;

    str = strrchr(tech, '/');
    if (str)
        str++;
    else
        str = tech;

    if (error)
        fprintf(stderr, "Error %s: %s\n", str, error);

    g_free(user_data);

    return 0;
}

static void technologies_power(char *technologies, int onoff)
{
    char *path;
    dbus_bool_t b = TRUE;

    if (onoff)
        b = TRUE;
    else
        b = FALSE;

    netctl_update_power(technologies, onoff);
    path = g_strdup_printf("/net/connman/technology/%s", technologies);
    __connmanctl_dbus_set_property(connection, path,
                                   "net.connman.Technology", enable_return, g_strdup(path),
                                   "Powered", DBUS_TYPE_BOOLEAN, &b);
}

void netctl_registered_call(void (*fun)(Massage_Type))
{
    call = fun;
}

void netctl_unregistered_call(void)
{
    call = NULL;
}

void netctl_wifi_scan(void)
{
    char *path = g_strdup("/net/connman/technology/wifi");

    __connmanctl_dbus_method_call(connection, CONNMAN_SERVICE, path,
                                  "net.connman.Technology", "Scan",
                                  scan_return, path, NULL, NULL);
}

void netctl_free_service_list(void)
{
    pthread_mutex_unlock(&service_mutex);
}

GList* netctl_get_service_list(void)
{
    pthread_mutex_lock(&service_mutex);
    return services_list;
}

void netctl_service_connect(char *service, char *pwd)
{
    const char *iface = "net.connman.Service";
    char *path;

    path = g_strdup_printf("/net/connman/service/%s", service);
    set_passphrase(pwd);
    __connmanctl_dbus_method_call(connection, CONNMAN_SERVICE, path,
                                  iface, "Connect", connect_return, path, NULL, NULL);
}

void netctl_service_disconnect(char *service)
{
    const char *iface = "net.connman.Service";
    char *path;

    path = g_strdup_printf("/net/connman/service/%s", service);

    __connmanctl_dbus_method_call(connection, CONNMAN_SERVICE, path,
                                  iface, "Disconnect", disconnect_return, path, NULL, NULL);
}

void netctl_service_config_timeservers(char *service, char *ntp)
{
    char *path;
    struct config_append append;
    char *cmd[2] = {ntp, NULL};

    memset(&append, 0, sizeof(struct config_append));
    append.opts = cmd;
    path = g_strdup_printf("/net/connman/service/%s", service);

    __connmanctl_dbus_set_property_array(connection,
                                         path, "net.connman.Service",
                                         config_return, g_strdup(service),
                                         "Timeservers.Configuration", DBUS_TYPE_STRING,
                                         config_append_str, &append);
    g_free(path);
}

void netctl_service_config_nameservers(char *service, char *dns)
{
    char *path;
    struct config_append append;
    char *cmd[2] = {dns, NULL};
    printf("%s,dns= %s\n", service, dns);
    memset(&append, 0, sizeof(struct config_append));
    append.opts = cmd;
    path = g_strdup_printf("/net/connman/service/%s", service);

    __connmanctl_dbus_set_property_array(connection,
                                         path, "net.connman.Service",
                                         config_return, g_strdup(service),
                                         "Nameservers.Configuration", DBUS_TYPE_STRING,
                                         config_append_str, &append);
    g_free(path);
}

void netctl_service_config_ipv4_dhcp(char *service)
{
    char *path;
    struct config_append append;
    char *cmd[2] = {"dhcp", NULL};

    memset(&append, 0, sizeof(struct config_append));
    append.opts = cmd;
    path = g_strdup_printf("/net/connman/service/%s", service);

    __connmanctl_dbus_set_property_dict(connection,
                                        path, "net.connman.Service",
                                        config_return, g_strdup(service),
                                        "IPv4.Configuration", DBUS_TYPE_STRING,
                                        config_append_ipv4, &append);
    g_free(path);
}

void netctl_service_config_ipv4_manual(char *service, char *addr, char *netmask, char *gateway)
{
    char *path;
    struct config_append append;
    char *cmd[5] = {"manual", addr, netmask, gateway, NULL};

    memset(&append, 0, sizeof(struct config_append));
    append.opts = cmd;
    path = g_strdup_printf("/net/connman/service/%s", service);

    __connmanctl_dbus_set_property_dict(connection,
                                        path, "net.connman.Service",
                                        config_return, g_strdup(service),
                                        "IPv4.Configuration", DBUS_TYPE_STRING,
                                        config_append_ipv4, &append);
    g_free(path);
}

void netctl_service_config_ipv4(char *service, struct IPv4Status *config)
{
    char *path;
    struct config_append append;
    char *cmd[5] = {config->Method, config->Address, config->Netmask, config->Gateway, NULL};

    memset(&append, 0, sizeof(struct config_append));
    append.opts = cmd;
    path = g_strdup_printf("/net/connman/service/%s", service);

    __connmanctl_dbus_set_property_dict(connection,
                                        path, "net.connman.Service",
                                        config_return, g_strdup(service),
                                        "IPv4.Configuration", DBUS_TYPE_STRING,
                                        config_append_ipv4, &append);
    g_free(path);
}

void netctl_service_config_remove(char *service)
{
    char *path;

    path = g_strdup_printf("/net/connman/service/%s", service);
    __connmanctl_dbus_method_call(connection,
                                  CONNMAN_SERVICE, path,
                                  "net.connman.Service", "Remove",
                                  config_return, path,
                                  NULL, NULL);
}

static int move_before_return(DBusMessageIter *iter, const char *error,
		void *user_data)
{
    struct move_service *services = user_data;
    char *service;
    char *target;

    if (error)
        printf("Error %s: %s\n", services->service, error);

    g_free(services->service);
    g_free(services->target);
    g_free(user_data);

    return 0;
}

static void move_before_append_args(DBusMessageIter *iter, void *user_data)
{
    char *path = user_data;

    dbus_message_iter_append_basic(iter,
        DBUS_TYPE_OBJECT_PATH, &path);

    return;
}

void netctl_service_move_before(char *service, char *target)
{
    struct move_service *services = g_new(struct move_service, 1);

    services->service = g_strdup_printf("/net/connman/service/%s", service);
    services->target = g_strdup_printf("/net/connman/service/%s", target);

    __connmanctl_dbus_method_call(connection,
                                  CONNMAN_SERVICE, services->service,
                                  "net.connman.Service", "MoveBefore",
                                  move_before_return, services,
                                  move_before_append_args, services->target);
}

void netctl_clock_config_timeservers(char *ntp)
{
    char *path;
    struct config_append append;
    char *cmd[3] = {ntp, NULL};

    memset(&append, 0, sizeof(struct config_append));
    append.opts = cmd;
    path = "/";

    __connmanctl_dbus_set_property_array(connection,
                                         path, "net.connman.Clock",
                                         config_return, NULL,
                                         "Timeservers", DBUS_TYPE_STRING,
                                         config_append_str, &append);
}

//manual,auto
void netctl_clock_config_timeupdates(char *mode)
{
    char *path = g_strdup("/");

    __connmanctl_dbus_set_property(connection, path,
                                   "net.connman.Clock", enable_return, path,
                                   "TimeUpdates", DBUS_TYPE_STRING, &mode);
}

//manual,auto
void netctl_clock_config_timezoneupdates(char *mode)
{
    char *path = g_strdup("/");

    __connmanctl_dbus_set_property(connection, path,
                                   "net.connman.Clock", enable_return, path,
                                   "TimezoneUpdates", DBUS_TYPE_STRING, &mode);
}

void netctl_clock_config_timezone(char *zone)
{
    char *path = g_strdup("/");

    __connmanctl_dbus_set_property(connection, path,
                                   "net.connman.Clock", enable_return, path,
                                   "Timezone", DBUS_TYPE_STRING, &zone);
}
/*
void netctl_clock_get_timezone(void)
{
    __connmanctl_dbus_method_call(connection,
                                  "/", CONNMAN_SERVICE,
                                  "net.connman.Clock", "GetConnections",
                                  populate_clock, NULL, NULL, NULL);
}
*/

int netctl_get_cell_power(void)
{
    return netctl_get_power("cellular");
}

int netctl_get_eth_power(void)
{
    return netctl_get_power("ethernet");
}

int netctl_get_wifi_power(void)
{
    return netctl_get_power("wifi");
}

void netctl_set_power(char *name, int onoff)
{
    printf("%s, %s, %d\n", __func__, name, onoff);
    technologies_power(name, onoff);
}

void netctl_set_cell_power(int onoff)
{
    technologies_power("cellular", onoff);
}

void netctl_set_eth_power(int onoff)
{
    technologies_power("ethernet", onoff);
}

void netctl_set_wifi_power(int onoff)
{
    technologies_power("wifi", onoff);
}


static void *network_priority_thread(void *arg)
{
    int cnt = 10;
    while (1) {
        struct NetworkPower *networkpower = database_networkpower_get("wifi");
        if (networkpower) {
            if (networkpower->power) {
                if (cnt++ > 10) {
                    cnt = 0;
                    netctl_wifi_scan();
                }
            }
        }

        sleep(1);
        pthread_mutex_lock(&service_mutex);
        GList* list_tmp = g_list_first(services_list);
        if (list_tmp) {
            struct PropertiesStatus *status_first = (struct PropertiesStatus *)list_tmp->data;
            list_tmp = list_tmp->next;
            if (g_str_equal(status_first->Type, "wifi")) {
                if (status_first->Favorite) {
                    while (list_tmp) {
                        struct PropertiesStatus *status = (struct PropertiesStatus *)list_tmp->data;
                        if (g_str_equal(status->Type, "ethernet") && g_str_equal(status->State, "ready")) {
                            netctl_service_move_before(status->service, status_first->service);
                            break;
                        }
                        list_tmp = list_tmp->next;
                    }
                }
            } else if (g_str_equal(status_first->Type, "ethernet")) {
                while (list_tmp) {
                    struct PropertiesStatus *status = (struct PropertiesStatus *)list_tmp->data;
                    if (g_str_equal(status->Type, "wifi") && status_first->Favorite) {
                        if (g_str_equal(status->State, "idle") && status->Favorite)
                            netctl_service_connect(status->service, "");

                        break;
                    }
                    list_tmp = list_tmp->next;
                }
            }
        }
        list_tmp = g_list_first(services_list);
        while (list_tmp) {
            struct PropertiesStatus *status = (struct PropertiesStatus *)list_tmp->data;
            if (g_str_equal(status->Type, "wifi")) {
                struct NetworkService *networkservice = (struct NetworkService *)database_networkservice_get(status->service);

                if (networkservice) {
                    if (status->Favorite != networkservice->Favorite) {
                        if (status->Favorite == 0)
                            netctl_service_connect(status->service, networkservice->password);
                        else
                            netctl_service_config_remove(status->service);
                    }
                } else {
                    if (status->Favorite == 1)
                        netctl_service_config_remove(status->service);
                }
            }
            list_tmp = list_tmp->next;
        }

        pthread_mutex_unlock(&service_mutex);
    }

    pthread_detach(pthread_self());
    pthread_exit(NULL);
}

void netctl_init(void)
{
    DBusError dbus_err;

    dbus_error_init(&dbus_err);
    connection = g_dbus_setup_bus(DBUS_BUS_SYSTEM, NULL, &dbus_err);
}

void netctl_run(void)
{
    pthread_t tid;
    pthread_create(&thread_id, NULL, (void*)netctl_thread, NULL);
    pthread_create(&tid, NULL, network_priority_thread, NULL);
}

void netctl_deinit(void)
{

}

void netctl_getdns(char *interface, char **dns1, char **dns2)
{
    pthread_mutex_lock(&service_mutex);
    GList* list_tmp = g_list_first(services_list);
    while (list_tmp) {
        struct PropertiesStatus *status = (struct PropertiesStatus *)list_tmp->data;
        if (status) {
            if (g_str_equal(status->Ethernet.Interface, interface) && !g_str_equal(status->Nameservers, "")) {
                char *c = status->Nameservers;
                while (c > 0) {
                    char d[16] = {0};
                    sscanf(c, "%s", d);
                    if (is_ipv4(d) == 0) {
                        if (*dns1 == NULL) {
                            *dns1 = g_strdup(d);
                        } else {
                            *dns2 = g_strdup(d);
                            break;
                        }
                    }
                    c = strchr(c, ' ');
                    if (c > 0)
                        c += 1;
                }
                break;
            }
        }
        list_tmp = list_tmp->next;
    }

    pthread_mutex_unlock(&service_mutex);
}
