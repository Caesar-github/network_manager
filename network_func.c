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
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/sockios.h>
#include <arpa/inet.h>

#include <glib.h>

#include <pthread.h>
#include <gdbus.h>

#include "json-c/json.h"
#include "network_func.h"

#define SIOCETHTOOL     0x8946
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define ETHTOOL_GSET        0x00000001 /* Get settings. */
#define ETHTOOL_SSET        0x00000002 /* Set settings. */

int get_ethernet_tool(char *interface, struct ethtool_cmd *ep)
{
    struct ifreq ifr, *ifrp;
    int fd;

    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, interface);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("Cannot get control socket");
        return -1;
    }

    int err;

    ep->cmd = ETHTOOL_GSET;
    ifr.ifr_data = (caddr_t)ep;
    err = ioctl(fd, SIOCETHTOOL, &ifr);
    close(fd);

    if (err != 0)
        return -1;

    return 0;
}

char *get_local_mac(char *interface)
{
    char *mac = NULL;
    struct ifreq ifr;
    int sd;

    bzero(&ifr, sizeof(struct ifreq));
    if( (sd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("get %s mac address socket creat error\n", interface);
        return mac;
    }

    strncpy(ifr.ifr_name, interface, sizeof(ifr.ifr_name) - 1);

    if(ioctl(sd, SIOCGIFHWADDR, &ifr) < 0) {
        //printf("get %s mac address error\n", interface);
        close(sd);
        return mac;
    }

    mac = g_strdup_printf("%02x:%02x:%02x:%02x:%02x:%02x",
        (unsigned char)ifr.ifr_hwaddr.sa_data[0],
        (unsigned char)ifr.ifr_hwaddr.sa_data[1],
        (unsigned char)ifr.ifr_hwaddr.sa_data[2],
        (unsigned char)ifr.ifr_hwaddr.sa_data[3],
        (unsigned char)ifr.ifr_hwaddr.sa_data[4],
        (unsigned char)ifr.ifr_hwaddr.sa_data[5]);

    close(sd);

    return mac;
}

char *get_local_ip(char *interface)
{
    char *ip = NULL;
    int sd;
    struct sockaddr_in sin;
    struct ifreq ifr;

    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (-1 == sd) {
        printf("socket error: %s\n", strerror(errno));
        return ip;
    }

    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
    ifr.ifr_name[IFNAMSIZ - 1] = 0;

    if (ioctl(sd, SIOCGIFADDR, &ifr) < 0) {
        printf("ioctl error: %s\n", strerror(errno));
        close(sd);
        return ip;
    }

    memcpy(&sin, &ifr.ifr_addr, sizeof(sin));
    ip = g_strdup_printf("%s", inet_ntoa(sin.sin_addr));

    close(sd);

    return ip;
}

char *get_local_netmask(char *interface)
{
    char *ip = NULL;
    int sd;
    struct sockaddr_in sin;
    struct ifreq ifr;

    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (-1 == sd) {
        printf("socket error: %s\n", strerror(errno));
        return ip;
    }

    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
    ifr.ifr_name[IFNAMSIZ - 1] = 0;

    if (ioctl(sd, SIOCGIFNETMASK, &ifr) < 0) {
        printf("ioctl error: %s\n", strerror(errno));
        close(sd);
        return ip;
    }

    memcpy(&sin, &ifr.ifr_netmask, sizeof(sin));
    ip = g_strdup_printf("%s", inet_ntoa(sin.sin_addr));

    close(sd);

    return ip;
}

char *get_gateway(char *interface)
{
    FILE *fp;
    char buf[512];
    char gateway[30];

    fp = popen("ip route", "r");
    if(NULL == fp) {
        perror("popen error");
        return NULL;
    }

    char *cmp = g_strdup_printf("dev %s scope link", interface);
    while(fgets(buf, sizeof(buf), fp) != NULL) {
        if (strstr(buf, cmp) && !strstr(buf, "/")) {
            sscanf(buf, "%s", gateway);
            pclose(fp);
            g_free(cmp);

            return g_strdup(gateway);
        }
    }

    pclose(fp);
    g_free(cmp);

    return NULL;
}

int is_ipv4(char *ip)
{
    char* ptr;
    int count = 0;
    char *str = g_strdup(ip);
    const char *p = str;

    while (*p != '\0') {
        if(*p == '.')
        count++;
        p++;
    }

    if (count != 3)
        goto err;

    count = 0;
    ptr = strtok(str, ".");
    while (ptr != NULL) {   
        count++;
        if (ptr[0] == '0' && isdigit(ptr[1]))
            goto err;

        int a = atoi(ptr);
        if (count == 1 && a == 0)
            goto err;

        if (a < 0 || a > 255)
            goto err;

        ptr = strtok(NULL, ".");
    }

    if(count == 4)
        return 0;
err:
    g_free(str);

    return -1;
}

int get_dns(char **dns1, char **dns2)
{
    FILE *fp;
    char buf[512];
    char dns[30];
    int i = 1;

    fp = popen("cat /etc/resolv.conf | grep \"nameserver\"", "r");
    if(NULL == fp) {
        perror("popen error");
        return -1;
    }

    while(fgets(buf, sizeof(buf), fp) != NULL) {
        memset(dns, 0, sizeof(dns));
        sscanf(buf, "%*s%s", dns);

        if (is_ipv4(dns) != 0)
            continue;

        if (i == 1)
            *dns1 = g_strdup(dns);
        else if(i == 2) {
            *dns2 = g_strdup(dns);
            break;
        }
        i++;

    }

    pclose(fp);

    return 0;
}