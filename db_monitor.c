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

#define TABLE_NETWORK_IP            "NetworkIP"
#define TABLE_NETWORK_SERVICE       "NetworkService"
#define TABLE_NETWORK_POWER         "NetworkPower"
#define TABLE_NTP    "ntp"

static GHashTable *db_networkpower_hash;
static GHashTable *db_networkip_hash;
static GHashTable *db_networkservice_hash;
static struct NtpCfg *ntp = NULL;

struct UserData {
    pthread_mutex_t mutex;
    char *json_str;
};

void *database_networkip_get(char *interface)
{
    void *val = g_hash_table_lookup(db_networkip_hash, interface);

    return val;
}

void *database_networkservice_get(char *service)
{
    void *val = g_hash_table_lookup(db_networkservice_hash, service);

    return val;
}

void *database_networkpower_get(char *type)
{
    void *val = g_hash_table_lookup(db_networkpower_hash, type);

    return val;
}

struct NtpCfg *database_ntp_get(void)
{
    return ntp;
}

void *database_networkservice_json_get(char *service)
{
    struct NetworkService *networkservice = g_hash_table_lookup(db_networkservice_hash, service);
    if (networkservice) {
        json_object *j_cfg = json_object_new_object();

        json_object_object_add(j_cfg, "sPassword", json_object_new_string(networkservice->password));
        json_object_object_add(j_cfg, "iFavorite", json_object_new_int(networkservice->Favorite));
        json_object_object_add(j_cfg, "iAutoconnect", json_object_new_int(networkservice->AutoConnect));

        return (void *)j_cfg;
    }

    return NULL;
}

void *database_networkip_json_get(char *interface)
{
    struct NetworkIP *networkip = g_hash_table_lookup(db_networkip_hash, interface);

    if (networkip) {
        json_object *j_cfg = json_object_new_object();

        json_object_object_add(j_cfg, "sV4Method", json_object_new_string(networkip->IPv4.Method));
        json_object_object_add(j_cfg, "sV4Address", json_object_new_string(networkip->IPv4.Address));
        json_object_object_add(j_cfg, "sV4Netmask", json_object_new_string(networkip->IPv4.Netmask));
        json_object_object_add(j_cfg, "sV4Gateway", json_object_new_string(networkip->IPv4.Gateway));
        json_object_object_add(j_cfg, "sDNS1", json_object_new_string(networkip->dns1));
        json_object_object_add(j_cfg, "sDNS2", json_object_new_string(networkip->dns2));

        return (void *)j_cfg;
    }

    return NULL;
}

void *database_networkpower_json_get(char *type)
{
    struct NetworkPower *networkpower = g_hash_table_lookup(db_networkpower_hash, type);

    if (networkpower) {
        json_object *j_cfg = json_object_new_object();

        json_object_object_add(j_cfg, "iPower", json_object_new_int(networkpower->power));

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
    } else if (g_str_equal(name, "sTimeZone")) {
        if (ntp->zone)
            g_free(ntp->zone);
        ntp->zone = g_strdup(data);
    } else if (g_str_equal(name, "iAutoMode")) {
        ntp->automode = *(int *)data;
    } else if (g_str_equal(name, "iRefreshTime")) {
        ntp->time = *(int *)data;
    }
}

static void append_path(DBusMessageIter *iter, void *user_data)
{
    const char *json = user_data;

    dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &json);
}

static void updatehash_network_ip(char *interface, char *name, void *data)
{
    struct NetworkIP *networkip = g_hash_table_lookup(db_networkip_hash, interface);

    if (networkip == NULL) {
        networkip = malloc(sizeof(struct NetworkIP));
        memset(networkip, 0, sizeof(struct NetworkIP));
        networkip->interface = g_strdup(interface);
        networkip->type = g_strdup("");
        networkip->IPv4.Method = g_strdup("");
        networkip->IPv4.Address = g_strdup("");
        networkip->IPv4.Netmask = g_strdup("");
        networkip->IPv4.Gateway = g_strdup("");
        networkip->dns1 = g_strdup("");
        networkip->dns2 = g_strdup("");
        g_hash_table_replace(db_networkip_hash, g_strdup(interface), (gpointer)networkip);
    }
    if (g_str_equal(name, "sV4Method")) {
        if (networkip->IPv4.Method)
            g_free(networkip->IPv4.Method);
        networkip->IPv4.Method = g_strdup(data);
    } else if (g_str_equal(name, "sV4Address")) {
        if (networkip->IPv4.Address)
            g_free(networkip->IPv4.Address);
        networkip->IPv4.Address = g_strdup(data);
    } else if (g_str_equal(name, "sV4Netmask")) {
        if (networkip->IPv4.Netmask)
            g_free(networkip->IPv4.Netmask);
        networkip->IPv4.Netmask = g_strdup(data);
    } else if (g_str_equal(name, "sV4Gateway")) {
        if (networkip->IPv4.Gateway)
            g_free(networkip->IPv4.Gateway);
        networkip->IPv4.Gateway = g_strdup(data);
    } else if (g_str_equal(name, "sDNS1")) {
        if (networkip->dns1)
            g_free(networkip->dns1);
        networkip->dns1 = g_strdup(data);
    } else if (g_str_equal(name, "sDNS2")) {
        if (networkip->dns2)
            g_free(networkip->dns2);
        networkip->dns2 = g_strdup(data);
    } else if (g_str_equal(name, "sType")) {
        if (networkip->type)
            g_free(networkip->type);
        networkip->type = g_strdup(data);
    } 
}

static void updatehash_network_power(char *type, char *name, void *data)
{
    struct NetworkPower *networkpower = g_hash_table_lookup(db_networkpower_hash, type);

    if (networkpower == NULL) {
        networkpower = malloc(sizeof(struct NetworkPower));
        memset(networkpower, 0, sizeof(struct NetworkPower));
        networkpower->type = g_strdup(type);
        g_hash_table_replace(db_networkpower_hash, g_strdup(type), (gpointer)networkpower);
    }
    if (g_str_equal(name, "iPower")) {
        networkpower->power = *(int *)data;
    }
}

static void deletehash_networkservice(char *service)
{
    struct NetworkService *networkservice = g_hash_table_lookup(db_networkservice_hash, service);
    if (networkservice) {
        g_hash_table_remove(db_networkservice_hash, service);
        if (networkservice->service)
            g_free(networkservice->service);
        if (networkservice->password)
            g_free(networkservice->password);
        g_free(networkservice);
    }
}

static void updatehash_networkservice(char *service, char *name, void *data)
{
    struct NetworkService *networkservice;

    networkservice = g_hash_table_lookup(db_networkservice_hash, service);

    if (networkservice == NULL) {
        networkservice = malloc(sizeof(struct NetworkService));
        memset(networkservice, 0, sizeof(struct NetworkService));
        networkservice->service = g_strdup(service);
        networkservice->password = g_strdup("");
        g_hash_table_replace(db_networkservice_hash, g_strdup(service), (gpointer)networkservice);
    }

    if (g_str_equal(name, "sPassword")) {
        if (networkservice->password)
            g_free(networkservice->password);
        networkservice->password = g_strdup(data);
    } else if (g_str_equal(name, "iAutoconnect")) {
        networkservice->AutoConnect = *(int *)data;
    } else if (g_str_equal(name, "iFavorite")) {
        networkservice->Favorite = *(int *)data;
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

    if (g_str_equal(table, TABLE_NETWORK_IP)) {
        char *interface = (char *)json_object_get_string(json_object_object_get(j_key, "sInterface"));
        char *cmd = (char *)json_object_get_string(json_object_object_get(j_cfg, "cmd"));

        if (g_str_equal(cmd, "Delete")) {

        } else if (g_str_equal(cmd, "Update")) {
            json_object_object_foreach(j_data, key, val) {
                void *data;
                int tmp;
                if (json_object_get_type(val) == json_type_int) {
                    tmp = (int)json_object_get_int(val);
                    data = (void *)&tmp;
                } else
                    data = (void *)json_object_get_string(val);
                updatehash_network_ip(interface, key, data);
            }
            SyncAllNetconfig();
        }
    } else if (g_str_equal(table, TABLE_NETWORK_POWER)) {
        char *type = (char *)json_object_get_string(json_object_object_get(j_key, "sType"));
        char *cmd = (char *)json_object_get_string(json_object_object_get(j_cfg, "cmd"));

        if (g_str_equal(cmd, "Delete")) {

        } else if (g_str_equal(cmd, "Update")) {
            json_object_object_foreach(j_data, key, val) {
                void *data;
                int tmp;
                if (json_object_get_type(val) == json_type_int) {
                    tmp = (int)json_object_get_int(val);
                    data = (void *)&tmp;
                } else
                    data = (void *)json_object_get_string(val);
                updatehash_network_power(type, key, data);
                if (g_str_equal(key, "iPower"))
                    netctl_set_power(type, tmp);
            }
        }
    } else if (g_str_equal(table, TABLE_NETWORK_SERVICE)) {
        char *service = (char *)json_object_get_string(json_object_object_get(j_key, "sService"));
        char *cmd = (char *)json_object_get_string(json_object_object_get(j_cfg, "cmd"));

        if (g_str_equal(cmd, "Delete")) {
            deletehash_networkservice(service);
        } else if (g_str_equal(cmd, "Update")) {
            json_object_object_foreach(j_data, key, val) {
                void *data;
                int tmp;
                if (json_object_get_type(val) == json_type_int) {
                    tmp = (int)json_object_get_int(val);
                    data = (void *)&tmp;
                } else
                    data = (void *)json_object_get_string(val);
                updatehash_networkservice(service, key, data);
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

static int populate_dbserver_get(DBusMessageIter *iter, const char *error,
                                            void *user_data)
{
    char *json_str;
    json_object *j_array;
    struct UserData *userdata = (struct UserData *)user_data;

    if (error) {
        if (userdata) {
            userdata->json_str = NULL;
            pthread_mutex_unlock(&userdata->mutex);
        }

        return 0;
    }

    dbus_message_iter_get_basic(iter, &json_str);

    if (userdata) {
        userdata->json_str = g_strdup(json_str);
        pthread_mutex_unlock(&userdata->mutex);
    }

    return 0;
}

static int populate_dbserver_get_ntp(char *json_str)
{
    json_object *j_array;
    json_object *j_ret;

    j_ret = json_tokener_parse(json_str);
    j_array = json_object_object_get(j_ret, "jData");
    int len = json_object_array_length(j_array);

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

static int populate_dbserver_networkservice_get(char *json_str)
{
    json_object *j_array;
    json_object *j_ret;

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
            updatehash_networkservice(service, key, data);
        }
    }
    json_object_put(j_ret);

    return 0;
}

static int populate_dbserver_networkip_get(char *json_str)
{
    json_object *j_ret;
    json_object *j_array;


    j_ret = json_tokener_parse(json_str);
    j_array = json_object_object_get(j_ret, "jData");

    int len = json_object_array_length(j_array);

    for (int i = 0; i < len; i++) {
        json_object *j_obj = json_object_array_get_idx(j_array, i);
        char *interface = (char *)json_object_get_string(json_object_object_get(j_obj, "sInterface"));

        json_object_object_foreach(j_obj, key, val) {
            void *data;
            int tmp;
            if (json_object_get_type(val) == json_type_int) {
                tmp = (int)json_object_get_int(val);
                data = (void *)&tmp;
            } else
                data = (void *)json_object_get_string(val);
            updatehash_network_ip(interface, key, data);
        }
    }
    json_object_put(j_ret);

    return 0;
}

static int populate_dbserver_networkpower_get(char *json_str)
{
    json_object *j_ret;
    json_object *j_array;

    j_ret = json_tokener_parse(json_str);
    j_array = json_object_object_get(j_ret, "jData");

    int len = json_object_array_length(j_array);

    for (int i = 0; i < len; i++) {
        json_object *j_obj = json_object_array_get_idx(j_array, i);
        char *type = (char *)json_object_get_string(json_object_object_get(j_obj, "sType"));

        json_object_object_foreach(j_obj, key, val) {
            void *data;
            int tmp;
            if (json_object_get_type(val) == json_type_int) {
                tmp = (int)json_object_get_int(val);
                data = (void *)&tmp;
            } else
                data = (void *)json_object_get_string(val);
            updatehash_network_power(type, key, data);
        }
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

static int dbserver_networkip_get(void)
{
    char *json_str;
    struct UserData userdata;

    memset(&userdata, 0, sizeof(struct UserData));
    pthread_mutex_init(&userdata.mutex, NULL);
    pthread_mutex_lock(&userdata.mutex);

    json_object *j_cfg = json_object_new_object();
    json_object *key = json_object_new_object();

    json_object_object_add(j_cfg, "table", json_object_new_string(TABLE_NETWORK_IP));
    json_object_object_add(j_cfg, "key", key);
    json_object_object_add(j_cfg, "data", json_object_new_string("*"));
    json_object_object_add(j_cfg, "cmd", json_object_new_string("Select"));

    json_str = (char *)json_object_to_json_string(j_cfg);

    dbus_helpers_method_call(connection,
                             DBSERVER, DBSERVER_PATH,
                             DBSERVER_NET_INTERFACE, "Cmd",
                             populate_dbserver_get, &userdata, append_path, json_str);

    pthread_mutex_lock(&userdata.mutex);
    pthread_mutex_unlock(&userdata.mutex);

    json_object_put(j_cfg);

    if (userdata.json_str) {
        populate_dbserver_networkip_get(userdata.json_str);
        g_free(userdata.json_str);
        return 0;
    }

    return -1;
}

static int dbserver_networkpower_get(void)
{
    char *json_str;
    struct UserData userdata;

    memset(&userdata, 0, sizeof(struct UserData));
    pthread_mutex_init(&userdata.mutex, NULL);
    pthread_mutex_lock(&userdata.mutex);
    
    json_object *j_cfg = json_object_new_object();
    json_object *key = json_object_new_object();

    json_object_object_add(j_cfg, "table", json_object_new_string(TABLE_NETWORK_POWER));
    json_object_object_add(j_cfg, "key", key);
    json_object_object_add(j_cfg, "data", json_object_new_string("*"));
    json_object_object_add(j_cfg, "cmd", json_object_new_string("Select"));

    json_str = (char *)json_object_to_json_string(j_cfg);

    dbus_helpers_method_call(connection,
                             DBSERVER, DBSERVER_PATH,
                             DBSERVER_NET_INTERFACE, "Cmd",
                             populate_dbserver_get, &userdata, append_path, json_str);

    pthread_mutex_lock(&userdata.mutex);
    pthread_mutex_unlock(&userdata.mutex);

    json_object_put(j_cfg);

    if (userdata.json_str) {
        populate_dbserver_networkpower_get(userdata.json_str);
        g_free(userdata.json_str);
        return 0;
    }

    return -1;
}

static int dbserver_ntp_get(void)
{
    char *json_str;
    struct UserData userdata;

    memset(&userdata, 0, sizeof(struct UserData));
    pthread_mutex_init(&userdata.mutex, NULL);
    pthread_mutex_lock(&userdata.mutex);

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
                             populate_dbserver_get, &userdata, append_path, json_str);

    pthread_mutex_lock(&userdata.mutex);
    pthread_mutex_unlock(&userdata.mutex);

    json_object_put(j_cfg);

    if (userdata.json_str) {
        populate_dbserver_get_ntp(userdata.json_str);
        g_free(userdata.json_str);
        return 0;
    }

    return -1;
}

static int dbserver_networkservice_get(void)
{
    char *json_str;
    struct UserData userdata;

    memset(&userdata, 0, sizeof(struct UserData));
    pthread_mutex_init(&userdata.mutex, NULL);
    pthread_mutex_lock(&userdata.mutex);

    json_object *j_cfg = json_object_new_object();
    json_object *key = json_object_new_object();

    json_object_object_add(j_cfg, "table", json_object_new_string(TABLE_NETWORK_SERVICE));
    json_object_object_add(j_cfg, "key", key);
    json_object_object_add(j_cfg, "data", json_object_new_string("*"));
    json_object_object_add(j_cfg, "cmd", json_object_new_string("Select"));

    json_str = (char *)json_object_to_json_string(j_cfg);

    dbus_helpers_method_call(connection,
                             DBSERVER, DBSERVER_PATH,
                             DBSERVER_NET_INTERFACE, "Cmd",
                             populate_dbserver_get, &userdata, append_path, json_str);

    pthread_mutex_lock(&userdata.mutex);
    pthread_mutex_unlock(&userdata.mutex);

    json_object_put(j_cfg);

    if (userdata.json_str) {
        populate_dbserver_networkservice_get(userdata.json_str);
        g_free(userdata.json_str);
        return 0;
    }

    return -1;
}

void dbserver_networkservice_set_connect(char *service, char *password, int *favorite, int *autoconnect)
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

    json_object_object_add(j_cfg, "table", json_object_new_string(TABLE_NETWORK_SERVICE));
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

    db_networkpower_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
                                          g_free, NULL);
    db_networkip_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
                                          g_free, NULL);
    db_networkservice_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
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

    while (dbserver_networkservice_get() != 0) {
        printf("dbserver_networkservice_get, wait dbserver.\n");
        usleep(50000);
    }

    while (dbserver_networkip_get() != 0) {
        printf("dbserver_networkip_get, wait dbserver.\n");
        usleep(50000);
    }

    while (dbserver_networkpower_get() != 0) {
        printf("dbserver_networkpower_get, wait dbserver.\n");
        usleep(50000);
    }

    while (dbserver_ntp_get() != 0) {
        printf("dbserver_ntp_get, wait dbserver.\n");
        usleep(50000);
    }
}
