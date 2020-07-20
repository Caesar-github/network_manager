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
#include "netctl.h"
#include "db_monitor.h"
#include "manage.h"
#include "udp_broadcast.h"
#include "port.h"
#include "log.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "main.c"

enum {
  LOG_ERROR,
  LOG_WARN,
  LOG_INFO,
  LOG_DEBUG
};

int enable_minilog = 0;
int netserver_log_level = LOG_INFO;

static void *main_init(void *arg)
{
    LOG_INFO("netserver init\n");
    netctl_init();
    database_init();
    port_init();
    manage_init();
    netctl_run();
    udp_broadcast_init();
    LOG_INFO("netserver finish\n");
}

int main( int argc , char ** argv)
{
#ifdef ENABLE_MINILOGGER
    enable_minilog = 1;
    __minilog_log_init(argv[0], NULL, false, false, "netserver","1.0");
#endif
    pthread_t thread_id;
    GMainLoop *main_loop;

    main_loop = g_main_loop_new(NULL, FALSE);

    database_hash_init();
    netctl_hash_init();
    pthread_create(&thread_id, NULL, (void*)main_init, NULL);

    g_main_loop_run(main_loop);
    netctl_deinit();
    if (main_loop)
        g_main_loop_unref(main_loop);

    return 0;
}
