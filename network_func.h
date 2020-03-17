#ifndef __NETWORK_FUNC_H__
#define __NETWORK_FUNC_H__

/* This should work for both 32 and 64 bit userland. */
struct ethtool_cmd {
        __uint32_t   cmd;
        __uint32_t   supported;      /* Features this interface supports */
        __uint32_t   advertising;    /* Features this interface advertises */
        __uint16_t   speed;          /* The forced speed, 10Mb, 100Mb, gigabit */
        __uint8_t    duplex;         /* Duplex, half or full */
        __uint8_t    port;           /* Which connector port */
        __uint8_t    phy_address;
        __uint8_t    transceiver;    /* Which transceiver to use */
        __uint8_t    autoneg;        /* Enable or disable autonegotiation */
        __uint32_t   maxtxpkt;       /* Tx pkts before generating tx int */
        __uint32_t   maxrxpkt;       /* Rx pkts before generating rx int */
        __uint32_t   reserved[4];
};

int get_ethernet_tool(char *interface, struct ethtool_cmd *ep);
char *get_local_mac(char *interface);
char *get_local_ip(char *interface);
char *get_local_netmask(char *interface);
char *get_gateway(char *interface);
int get_dns(char **dns1, char **dns2);
int is_ipv4(char *ip);

#endif