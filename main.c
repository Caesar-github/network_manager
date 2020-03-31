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

static void *main_init(void *arg)
{
    printf("netserver init\n");
    netctl_init();
    database_init();
    manage_init();
    netctl_run();
    udp_broadcast_init();
    printf("netserver finish\n");
}

int main( int argc , char ** argv)
{
    pthread_t thread_id;
    GMainLoop *main_loop;

    main_loop = g_main_loop_new(NULL, FALSE);

    pthread_create(&thread_id, NULL, (void*)main_init, NULL);

    g_main_loop_run(main_loop);
    netctl_deinit();
    if (main_loop)
        g_main_loop_unref(main_loop);

    return 0;
}
