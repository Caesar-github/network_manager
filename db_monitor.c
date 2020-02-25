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

#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>

#include <pthread.h>
#include <gdbus.h>

#include "json-c/json.h"
#include "dbus_helpers.h"
#include "netctl.h"
#include "db_monitor.h"

static DBusConnection *connection = 0;

#define DBSERVER  "rockchip.dbserver"
#define DBSERVER_PATH      "/"

#define DBSERVER_NET_INTERFACE  DBSERVER ".net"
#define DBSERVER_POWER_INTERFACE    DBSERVER ".power"

#define TABLE_NETCONFIG    "netconfig"
#define TABLE_POWER    "power"
#define TABLE_NTP    "ntp"

static GHashTable *db_power_hash;
static GHashTable *db_netconfig_hash;
static struct NtpCfg *ntp = NULL;

int database_get_power(char *name, int *power)
{
    int *val = g_hash_table_lookup(db_power_hash, name);
    if (!val)
        return -1;
    *power = *val;
    return 0;
}

void *database_get_netconfig(char *service)
{
    void *val = g_hash_table_lookup(db_netconfig_hash, service);

    return val;
}

int database_get_ntp_time(void)
{
    return ntp->time;
}

struct NtpCfg *database_get_ntp(void)
{
    return ntp;
}

void *database_get_netconfig_json(char *service)
{
    struct ConfigStatus *status = g_hash_table_lookup(db_netconfig_hash, service);
    if (status) {
        json_object *j_cfg = json_object_new_object();

        json_object_object_add(j_cfg, "sPassword", json_object_new_string(status->password));
        json_object_object_add(j_cfg, "iFavorite", json_object_new_int(status->Favorite));
        json_object_object_add(j_cfg, "iAutoconnect", json_object_new_int(status->AutoConnect));
        json_object_object_add(j_cfg, "sV4Method", json_object_new_string(status->IPv4.Method));
        json_object_object_add(j_cfg, "sV4Address", json_object_new_string(status->IPv4.Address));
        json_object_object_add(j_cfg, "sV4Netmask", json_object_new_string(status->IPv4.Netmask));
        json_object_object_add(j_cfg, "sV4Gateway", json_object_new_string(status->IPv4.Gateway));
        json_object_object_add(j_cfg, "sDNS", json_object_new_string(status->Nameservers));

        return (void *)j_cfg;
    }

    return NULL;
}

static void updatentp(char *name, void *data)
{
    if (ntp == NULL) {
        ntp = malloc(sizeof(struct NtpCfg));
        memset(ntp, 0, sizeof(struct NtpCfg));
    }

    if (g_str_equal(name, "sNtpServers")) {
        if (ntp->servers)
            g_free(ntp->servers);
        ntp->servers = g_strdup(data);
        printf("%s servers = %s\n", __func__, ntp->servers);
    } else if (g_str_equal(name, "sTimeZone")) {
        if (ntp->zone)
            g_free(ntp->zone);
        ntp->zone = g_strdup(data);
        printf("%s zone = %s\n", __func__, ntp->zone);
    } else if (g_str_equal(name, "iAutoMode")) {
        ntp->automode = *(int *)data;
        printf("%s automode = %d\n", __func__, ntp->automode);
    } else if (g_str_equal(name, "iRefreshTime")) {
        ntp->time = *(int *)data;
        printf("%s time = %d\n", __func__, ntp->time);
    }
}

static void append_path(DBusMessageIter *iter, void *user_data)
{
    const char *json = user_data;

    dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &json);
}

static void updatehash_power(char *name, int power)
{
    int *val = g_hash_table_lookup(db_power_hash, name);
    if (val == NULL) {
        val = malloc(sizeof(int));
        memset(val, 0, sizeof(int));
        g_hash_table_replace(db_power_hash, g_strdup(name), (gpointer)val);
    }
    *val = power;
}

static void deletehash_netconfig(char *service)
{
    struct ConfigStatus *status = g_hash_table_lookup(db_netconfig_hash, service);
    if (status) {
        g_hash_table_remove(db_netconfig_hash, service);
        if (status->service)
            g_free(status->service);
        if (status->Nameservers)
            g_free(status->Nameservers);
        if (status->password)
            g_free(status->password);
        if (status->IPv4.Address)
            g_free(status->IPv4.Address);
        if (status->IPv4.Gateway)
            g_free(status->IPv4.Gateway);
        if (status->IPv4.Method)
            g_free(status->IPv4.Method);
        if (status->IPv4.Netmask)
            g_free(status->IPv4.Netmask);
        g_free(status);
    }
}

static void updatehash_netconfig(char *service, char *name, void *data)
{
    struct ConfigStatus *status;

    status = g_hash_table_lookup(db_netconfig_hash, service);

    if (status == NULL) {
        status = malloc(sizeof(struct ConfigStatus));
        memset(status, 0, sizeof(struct ConfigStatus));
        status->service = g_strdup(service);
        status->IPv4.Method = g_strdup("");
        status->IPv4.Address = g_strdup("");
        status->IPv4.Netmask = g_strdup("");
        status->IPv4.Gateway = g_strdup("");
        status->Nameservers = g_strdup("");
        status->password = g_strdup("");
        g_hash_table_replace(db_netconfig_hash, g_strdup(service), (gpointer)status);
    }

    if (g_str_equal(name, "sPassword")) {
        if (status->password)
            g_free(status->password);
        status->password = g_strdup(data);
    } else if (g_str_equal(name, "iAutoconnect")) {
        status->AutoConnect = *(int *)data;
    } else if (g_str_equal(name, "iFavorite")) {
        status->Favorite = *(int *)data;
    } else if (g_str_equal(name, "sV4Method")) {
        if (status->IPv4.Method)
            g_free(status->IPv4.Method);
        status->IPv4.Method = g_strdup(data);
    } else if (g_str_equal(name, "sV4Address")) {
        if (status->IPv4.Address)
            g_free(status->IPv4.Address);
        status->IPv4.Address = g_strdup(data);
    } else if (g_str_equal(name, "sV4Netmask")) {
        if (status->IPv4.Netmask)
            g_free(status->IPv4.Netmask);
        status->IPv4.Netmask = g_strdup(data);
    } else if (g_str_equal(name, "sV4Gateway")) {
        if (status->IPv4.Gateway)
            g_free(status->IPv4.Gateway);
        status->IPv4.Gateway = g_strdup(data);
    } else if (g_str_equal(name, "sDNS")) {
        if (status->Nameservers)
            g_free(status->Nameservers);
        status->Nameservers = g_strdup(data);
    }
}

static void DataChanged(char *json_str)
{
    json_object *j_cfg;
    json_object *j_key = 0;
    json_object *j_data = 0;
    char *table = 0;

    j_cfg = json_tokener_parse(json_str);

    table = (char *)json_object_get_string(json_object_object_get(j_cfg, "table"));
    j_key = json_object_object_get(j_cfg, "key");
    j_data = json_object_object_get(j_cfg, "data");

    if (g_str_equal(table, "power")) {
        char *name = (char *)json_object_get_string(json_object_object_get(j_key, "sName"));
        int power = json_object_get_int(json_object_object_get(j_data, "iPower"));

        updatehash_power(name, power);
        netctl_set_power(name, power);
    } else if (g_str_equal(table, "netconfig")) {
        char *service = (char *)json_object_get_string(json_object_object_get(j_key, "sService"));
        char *cmd = (char *)json_object_get_string(json_object_object_get(j_cfg, "cmd"));

        if (g_str_equal(cmd, "Delete")) {
            deletehash_netconfig(service);
        } else if (g_str_equal(cmd, "Update")) {
            json_object_object_foreach(j_data, key, val) {
                void *data;
                int tmp;
                if (json_object_get_type(val) == json_type_int) {
                    tmp = (int)json_object_get_int(val);
                    data = (void *)&tmp;
                } else
                    data = (void *)json_object_get_string(val);
                updatehash_netconfig(service, key, data);
            }
            SyncOneNetconfig(service);
        }
    } else if (g_str_equal(table, "ntp")) {
        char *cmd = (char *)json_object_get_string(json_object_object_get(j_cfg, "cmd"));
        if (g_str_equal(cmd, "Update")) {
            json_object_object_foreach(j_data, key, val) {
                void *data;
                int tmp;
                if (json_object_get_type(val) == json_type_int) {
                    tmp = (int)json_object_get_int(val);
                    data = (void *)&tmp;
                } else
                    data = (void *)json_object_get_string(val);
                updatentp(key, data);
            }
            syncntp();
            synczone();
        }
    }
    json_object_put(j_cfg);
}

static int populate_dbserver_get_ntp(DBusMessageIter *iter, const char *error,
                                     void *user_data)
{
    char *json_str;
    json_object *j_array;
    json_object *j_ret;

    if (error) {
        printf("%s err\n", __func__);
        return 0;
    }

    dbus_message_iter_get_basic(iter, &json_str);
    printf("%s, json_str = %s\n", __func__, json_str);
    j_ret = json_tokener_parse(json_str);
    j_array = json_object_object_get(j_ret, "jData");
    int len = json_object_array_length(j_array);
    printf("%s, len = %d\n", __func__, len);
    for (int i = 0; i < len; i++) {
        json_object *j_data = json_object_array_get_idx(j_array, i);
        json_object_object_foreach(j_data, key, val) {
            void *data;
            int tmp;
            if (json_object_get_type(val) == json_type_int) {
                tmp = (int)json_object_get_int(val);
                data = (void *)&tmp;
            } else
                data = (void *)json_object_get_string(val);
            updatentp(key, data);
        }
    }
    json_object_put(j_ret);

    return 0;
}

static int populate_dbserver_get_netconfig(DBusMessageIter *iter, const char *error,
                                           void *user_data)
{
    char *json_str;
    json_object *j_array;
    json_object *j_ret;

    if (error) {
        printf("%s err\n", __func__);
        return 0;
    }

    dbus_message_iter_get_basic(iter, &json_str);

    j_ret = json_tokener_parse(json_str);
    j_array = json_object_object_get(j_ret, "jData");
    int len = json_object_array_length(j_array);

    for (int i = 0; i < len; i++) {
        json_object *j_obj = json_object_array_get_idx(j_array, i);
        char *service = (char *)json_object_get_string(json_object_object_get(j_obj, "sService"));
        json_object_object_foreach(j_obj, key, val) {
            void *data;
            int tmp;
            if (json_object_get_type(val) == json_type_int) {
                tmp = (int)json_object_get_int(val);
                data = (void *)&tmp;
            } else
                data = (void *)json_object_get_string(val);
            updatehash_netconfig(service, key, data);
        }
    }
    json_object_put(j_ret);
    return 0;
}

static int populate_dbserver_get_power(DBusMessageIter *iter, const char *error,
                                       void *user_data)
{
    json_object *j_ret;
    char *json_str;
    json_object *j_array;

    if (error) {
        printf("%s err\n", __func__);
        return 0;
    }

    dbus_message_iter_get_basic(iter, &json_str);

    j_ret = json_tokener_parse(json_str);
    j_array = json_object_object_get(j_ret, "jData");

    int len = json_object_array_length(j_array);

    for (int i = 0; i < len; i++) {
        json_object *j_obj = json_object_array_get_idx(j_array, i);
        char *name = (char *)json_object_get_string(json_object_object_get(j_obj, "sName"));
        int power = json_object_get_int(json_object_object_get(j_obj, "iPower"));

        updatehash_power(name, power);
    }
    json_object_put(j_ret);

    return 0;
}

static DBusHandlerResult database_monitor_changed(
    DBusConnection *connection,
    DBusMessage *message, void *user_data)
{
    bool *enabled = user_data;
    DBusMessageIter iter;
    DBusHandlerResult handled;

    handled = DBUS_HANDLER_RESULT_HANDLED;
    if (dbus_message_is_signal(message, DBSERVER_NET_INTERFACE,
                               "DataChanged")) {
        char *json_str;

        dbus_message_iter_init(message, &iter);
        dbus_message_iter_get_basic(&iter, &json_str);
        DataChanged(json_str);

        return handled;
    }

    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static void dbserver_power_get(void)
{
    char *json_str;
    json_object *j_cfg = json_object_new_object();
    json_object *key = json_object_new_object();

    json_object_object_add(j_cfg, "table", json_object_new_string(TABLE_POWER));
    json_object_object_add(j_cfg, "key", key);
    json_object_object_add(j_cfg, "data", json_object_new_string("*"));
    json_object_object_add(j_cfg, "cmd", json_object_new_string("Select"));

    json_str = (char *)json_object_to_json_string(j_cfg);

    dbus_helpers_method_call(connection,
                             DBSERVER, DBSERVER_PATH,
                             DBSERVER_NET_INTERFACE, "Cmd",
                             populate_dbserver_get_power, NULL, append_path, json_str);

    json_object_put(j_cfg);
}

static void dbserver_ntp_get(void)
{
    char *json_str;

    json_object *j_cfg = json_object_new_object();
    json_object *key = json_object_new_object();

    json_object_object_add(j_cfg, "table", json_object_new_string(TABLE_NTP));
    json_object_object_add(j_cfg, "key", key);
    json_object_object_add(j_cfg, "data", json_object_new_string("*"));
    json_object_object_add(j_cfg, "cmd", json_object_new_string("Select"));

    json_str = (char *)json_object_to_json_string(j_cfg);

    dbus_helpers_method_call(connection,
                             DBSERVER, DBSERVER_PATH,
                             DBSERVER_NET_INTERFACE, "Cmd",
                             populate_dbserver_get_ntp, NULL, append_path, json_str);

    json_object_put(j_cfg);
}

static void dbserver_netconfig_get(void)
{
    char *json_str;

    json_object *j_cfg = json_object_new_object();
    json_object *key = json_object_new_object();

    json_object_object_add(j_cfg, "table", json_object_new_string(TABLE_NETCONFIG));
    json_object_object_add(j_cfg, "key", key);
    json_object_object_add(j_cfg, "data", json_object_new_string("*"));
    json_object_object_add(j_cfg, "cmd", json_object_new_string("Select"));

    json_str = (char *)json_object_to_json_string(j_cfg);

    dbus_helpers_method_call(connection,
                             DBSERVER, DBSERVER_PATH,
                             DBSERVER_NET_INTERFACE, "Cmd",
                             populate_dbserver_get_netconfig, NULL, append_path, json_str);

    json_object_put(j_cfg);
}

void dbserver_netconfig_set_connect(char *service, char *password, int *favorite, int *autoconnect)
{
    char *json_config;
    json_object *j_cfg = json_object_new_object();
    json_object *key = json_object_new_object();
    json_object *data = json_object_new_object();

    json_object_object_add(key, "sService", json_object_new_string(service));
    if (password)
        json_object_object_add(data, "sPassword", json_object_new_string(password));
    if (favorite)
        json_object_object_add(data, "iFavorite", json_object_new_int(*favorite));
    if (autoconnect)
        json_object_object_add(data, "iAutoconnect", json_object_new_int(*autoconnect));

    json_object_object_add(j_cfg, "table", json_object_new_string(TABLE_NETCONFIG));
    json_object_object_add(j_cfg, "key", key);
    json_object_object_add(j_cfg, "data", data);
    json_object_object_add(j_cfg, "cmd", json_object_new_string("Update"));

    json_config = (char *)json_object_to_json_string(j_cfg);

    dbus_helpers_method_call(connection,
                             DBSERVER, DBSERVER_PATH,
                             DBSERVER_NET_INTERFACE, "Update",
                             NULL, NULL, append_path, json_config);
    json_object_put(j_cfg);
}

void database_init(void)
{
    DBusError err;

    db_power_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
                                          g_free, NULL);
    db_netconfig_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
                                              g_free, NULL);

    dbus_error_init(&err);
    connection = g_dbus_setup_bus(DBUS_BUS_SYSTEM, NULL, &err);

    dbus_connection_add_filter(connection,
                               database_monitor_changed, NULL, NULL);

    dbus_bus_add_match(connection,
                       "type='signal',interface='rockchip.dbserver.net'", &err);

    if (dbus_error_is_set(&err)) {
        fprintf(stderr, "Error: %s\n", err.message);
        return;
    }
    dbserver_power_get();
    dbserver_netconfig_get();
    dbserver_ntp_get();
}
