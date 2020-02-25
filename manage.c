#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>
#include <ctype.h>
#include <inttypes.h>
#include <sys/prctl.h>

#include <glib.h>

#include <pthread.h>
#include <gdbus.h>

#include "json-c/json.h"
#include "manage.h"
#include "dbus.h"
#include "dbus_helpers.h"
#include "netctl.h"
#include "db_monitor.h"

#define MSG_CMD_ADD_TECH   1

static DBusConnection *connection = 0;

static gboolean power_send_changed(char *name, void *val)
{
    DBusMessage *signal;
    DBusMessageIter iter;

    signal = dbus_message_new_signal(NETSERVER_PATH,
                                     NETSERVER_INTERFACE, "PowerChanged");
    if (!signal)
        return FALSE;

    dbus_message_iter_init_append(signal, &iter);
    dbus_property_append_basic(&iter, name, DBUS_TYPE_BYTE, val);

    dbus_connection_send(connection, signal, NULL);
    dbus_message_unref(signal);

    return FALSE;
}

static DBusMessage *get_config(DBusConnection *conn,
                               DBusMessage *msg, void *data)
{
    const char *sender, *service;
    const char *str;
    DBusMessage *reply;
    DBusMessageIter array;
    dbus_bool_t onoff;
    json_object *j_array = json_object_new_array();
    GList* list = netctl_get_service_list();

    sender = dbus_message_get_sender(msg);

    dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &service,
                          DBUS_TYPE_INVALID);

    if (g_str_equal(service, "")) {
        while (list) {
            struct PropertiesStatus *status = (struct PropertiesStatus *)list->data;
            json_object *j_cfg = json_object_new_object();
            json_object *j_ipv4 = json_object_new_object();
            json_object *j_eth = json_object_new_object();
            json_object *j_db = (json_object *)database_get_netconfig_json(status->service);

            if (status->service)
                json_object_object_add(j_cfg, "sService", json_object_new_string(status->service));
            if (status->Nameservers)
                json_object_object_add(j_cfg, "sDNS", json_object_new_string(status->Nameservers));
            if (status->Security)
                json_object_object_add(j_cfg, "sSecurity", json_object_new_string(status->Security));
            if (status->Ethernet.Method)
                json_object_object_add(j_eth, "sMethod", json_object_new_string(status->Ethernet.Method));
            if (status->Ethernet.Interface)
                json_object_object_add(j_eth, "sInterface", json_object_new_string(status->Ethernet.Interface));
            if (status->Ethernet.Address)
                json_object_object_add(j_eth, "sAddress", json_object_new_string(status->Ethernet.Address));
            if (status->IPv4.Method)
                json_object_object_add(j_ipv4, "sV4Method", json_object_new_string(status->IPv4.Method));
            if (status->IPv4.Address)
                json_object_object_add(j_ipv4, "sV4Address", json_object_new_string(status->IPv4.Address));
            if (status->IPv4.Netmask)
                json_object_object_add(j_ipv4, "sV4Netmask", json_object_new_string(status->IPv4.Netmask));
            if (status->IPv4.Gateway)
                json_object_object_add(j_ipv4, "sV4Gateway", json_object_new_string(status->IPv4.Gateway));
            json_object_object_add(j_cfg, "ipv4", j_ipv4);
            json_object_object_add(j_cfg, "ethernet", j_eth);

            if (j_db)
                json_object_object_add(j_cfg, "dbconfig", j_db);
            json_object_array_add(j_array, j_cfg);
            list = list->next;
        }
    } else {
        while (list) {
            struct PropertiesStatus *status = (struct PropertiesStatus *)list->data;
            if (g_str_equal(status->service, service)) {
                json_object *j_cfg = json_object_new_object();
                json_object *j_ipv4 = json_object_new_object();
                json_object *j_eth = json_object_new_object();
                json_object *j_db = (json_object *)database_get_netconfig_json(status->service);

                if (status->service)
                    json_object_object_add(j_cfg, "sService", json_object_new_string(status->service));
                if (status->Nameservers)
                    json_object_object_add(j_cfg, "sDNS", json_object_new_string(status->Nameservers));
                if (status->Security)
                    json_object_object_add(j_cfg, "sSecurity", json_object_new_string(status->Security));
                if (status->Ethernet.Method)
                    json_object_object_add(j_eth, "sV4Method", json_object_new_string(status->Ethernet.Method));
                if (status->Ethernet.Interface)
                    json_object_object_add(j_eth, "sInterface", json_object_new_string(status->Ethernet.Interface));
                if (status->Ethernet.Address)
                    json_object_object_add(j_eth, "sAddress", json_object_new_string(status->Ethernet.Address));
                if (status->IPv4.Method)
                    json_object_object_add(j_ipv4, "sV4Method", json_object_new_string(status->IPv4.Method));
                if (status->IPv4.Address)
                    json_object_object_add(j_ipv4, "sV4Address", json_object_new_string(status->IPv4.Address));
                if (status->IPv4.Netmask)
                    json_object_object_add(j_ipv4, "sV4Netmask", json_object_new_string(status->IPv4.Netmask));
                if (status->IPv4.Gateway)
                    json_object_object_add(j_ipv4, "sV4Gateway", json_object_new_string(status->IPv4.Gateway));
                json_object_object_add(j_cfg, "ipv4", j_ipv4);
                json_object_object_add(j_cfg, "ethernet", j_eth);

                if (j_db)
                    json_object_object_add(j_cfg, "dbconfig", j_db);
                json_object_array_add(j_array, j_cfg);
            }
            list = list->next;
        }
    }

    str = json_object_to_json_string(j_array);

    reply = dbus_message_new_method_return(msg);
    if (!reply)
        return NULL;

    dbus_message_iter_init_append(reply, &array);
    dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING, &str);

    json_object_put(j_array);
    netctl_free_service_list();

    return reply;
}

static DBusMessage *get_service(DBusConnection *conn,
                                DBusMessage *msg, void *data)
{
    const char *sender, *type;
    const char *str;
    DBusMessage *reply;
    DBusMessageIter array;
    dbus_bool_t onoff;
    json_object *j_array = json_object_new_array();
    GList* list = netctl_get_service_list();

    sender = dbus_message_get_sender(msg);

    dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &type,
                          DBUS_TYPE_INVALID);

    if (g_str_equal(type, "")) {
        while (list) {
            struct PropertiesStatus *status = (struct PropertiesStatus *)list->data;

            json_object *j_cfg = json_object_new_object();
            if (status->service)
                json_object_object_add(j_cfg, "sService", json_object_new_string(status->service));
            if (status->Type)
                json_object_object_add(j_cfg, "sType", json_object_new_string(status->Type));
            if (status->State)
                json_object_object_add(j_cfg, "sState", json_object_new_string(status->State));
            if (status->Name)
                json_object_object_add(j_cfg, "sName", json_object_new_string(status->Name));
            if (status->Security)
                json_object_object_add(j_cfg, "sSecurity", json_object_new_string(status->Security));
            json_object_object_add(j_cfg, "Favorite", json_object_new_int(status->Favorite));
            json_object_object_add(j_cfg, "Strength", json_object_new_int(status->Strength));

            json_object_array_add(j_array, j_cfg);
            list = list->next;
        }
    } else {
        while (list) {
            struct PropertiesStatus *status = (struct PropertiesStatus *)list->data;

            if (g_str_equal(status->Type, type)) {
                json_object *j_cfg = json_object_new_object();
                if (status->service)
                    json_object_object_add(j_cfg, "sService", json_object_new_string(status->service));
                if (status->Type)
                    json_object_object_add(j_cfg, "sType", json_object_new_string(status->Type));
                if (status->State)
                    json_object_object_add(j_cfg, "sState", json_object_new_string(status->State));
                if (status->Name)
                    json_object_object_add(j_cfg, "sName", json_object_new_string(status->Name));
                if (status->Security)
                    json_object_object_add(j_cfg, "sSecurity", json_object_new_string(status->Security));
                json_object_object_add(j_cfg, "Favorite", json_object_new_int(status->Favorite));
                json_object_object_add(j_cfg, "Strength", json_object_new_int(status->Strength));
                json_object_array_add(j_array, j_cfg);
            }
            list = list->next;
        }
    }

    str = json_object_to_json_string(j_array);

    reply = dbus_message_new_method_return(msg);
    if (!reply)
        return NULL;

    dbus_message_iter_init_append(reply, &array);
    dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING, &str);

    json_object_put(j_array);
    netctl_free_service_list();
    return reply;
}

static DBusMessage *scanwifi(DBusConnection *conn,
                             DBusMessage *msg, void *data)
{
    netctl_wifi_scan();
    return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static const GDBusMethodTable server_methods[] = {
    {
        GDBUS_METHOD("GetService",
        GDBUS_ARGS({ "type", "s" }), GDBUS_ARGS({ "json", "s" }),
        get_service)
    },
    {
        GDBUS_METHOD("GetConfig",
        GDBUS_ARGS({ "service", "s" }), GDBUS_ARGS({ "json", "s" }),
        get_config)
    },
    {
        GDBUS_ASYNC_METHOD("ScanWifi",
        NULL, NULL, scanwifi)
    },
    { },
};

static const GDBusSignalTable server_signals[] = {
    {
        GDBUS_SIGNAL("PowerChanged",
        GDBUS_ARGS({ "name", "s" }, { "value", "v" }))
    },
    { },
};

static int dbus_manager_init(void)
{
    g_dbus_register_interface(connection, "/",
                              NETSERVER_INTERFACE,
                              server_methods,
                              server_signals, NULL, NULL, NULL);

    return 0;
}

void manage_init(void)
{
    pthread_t tid;
    DBusError dbus_err;
    DBusConnection *dbus_conn;

    dbus_error_init(&dbus_err);
    dbus_conn = g_dbus_setup_bus(DBUS_BUS_SYSTEM, NETSERVER, &dbus_err);
    connection = dbus_conn;
    if (!connection) {
        printf("%s connect %s fail\n", __func__, NETSERVER);
        return;
    }
    dbus_manager_init();
}
