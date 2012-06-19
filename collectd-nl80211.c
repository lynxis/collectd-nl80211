/* collectd headers */

#include <linux/nl80211.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <net/if.h>
#include <unistd.h>

#include <net/ethernet.h>

#include <string.h>

#include "collectd.h"
#include "common.h"
#include "plugin.h"

#define log_warn(...) WARNING ("nl80211: " __VA_ARGS__)
#define log_info(...) WARNING ("nl80211: " __VA_ARGS__)
#define log_debug(...) WARNING ("nl80211: " __VA_ARGS__)

static const char *config_keys[] =
{
    "interface",
    NULL
};

static int config_keys_num = 1;

struct cnl80211_interface {
    char *interface;
    short ignore;
    struct cnl80211_interface *next;
};

struct cnl80211_station {
    unsigned char mac[ETH_ALEN];
    uint32_t rx_bytes;
    uint32_t tx_bytes;
    uint32_t rx_pkg;
    uint32_t tx_pkg;
    uint32_t tx_retries;
    uint32_t tx_failed;
    uint32_t beacon_loss;
    uint32_t inactive_time;
    uint32_t connection_time;
    uint8_t signal;
    uint16_t mask;
    struct cnl80211_station *next;
};

struct cnl80211_station_interface {
    char interface[20];
    int num_stations;
    struct cnl80211_station *stations;
    struct cnl80211_station_interface *next;
};

struct cnl80211_ctx {
    struct nl_sock *sock;
    int family;
    struct cnl80211_interface *interfaces;
    int stopReceiving; // used to stop receiving loop
    struct cnl80211_station_interface *station_iface;
    struct nl_cb *cb;
};


static struct cnl80211_ctx *ctx = NULL;


static void addInterface(char *iface, short ignore) {
    struct cnl80211_interface **iter = &(ctx->interfaces);

    while(*iter != NULL) {
        iter = &((*iter)->next);
    }
    (*iter) = (struct cnl80211_interface *) calloc(1, sizeof(struct cnl80211_interface));
    (*iter)->interface = strdup(iface);
    (*iter)->ignore = ignore;
}

void mac_addr_n2a(char *mac_addr, unsigned char *arg)
{
    int i, l;

    l = 0;
    for (i = 0; i < ETH_ALEN ; i++) {
        if (i == 0) {
            sprintf(mac_addr+l, "%02x", arg[i]);
            l += 2;
        } else {
            sprintf(mac_addr+l, ":%02x", arg[i]);
            l += 3;
        }
    }
}


static int cnl80211_config (const char *key, const char *value) {
    if(ctx == NULL) {
        ctx = (struct cnl80211_ctx *) calloc(1, sizeof(struct cnl80211_ctx));
    }
    if(strcasecmp(key, "interface") == 0) {
        addInterface(value, 0);
    } else {
        return 1;
    }
    return 0;
}


static int nl80211_shutdown() {
    return 0;
}

static int cnl80211_read_survey() {
    return 0;
}

static int ack_handler(struct nl_msg *msg, void *arg) {
    printf("Ack received\n");
    return 0;
}

static int parse_err_nl_cb(struct sockaddr_nl *nla, struct nlmsgerr *nlerr, void *arg) {
    printf("CallbackError called");
    return 0;
}

static int finish_handler(struct nl_msg *msg, void*arg) {
    ctx->stopReceiving = 0;
    return NL_SKIP;
}

static int station_dump_handler(struct nl_msg *msg, void *arg) {
    struct cnl80211_station_interface **all_ifaces = (struct cnl80211_station_interface **) arg;
    struct cnl80211_station_interface *iface = NULL;
    struct cnl80211_station *station = NULL;
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    char dev[20], mac[ETH_ALEN];

    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct nlattr *tb[NL80211_ATTR_MAX];
    struct nlattr *sinfo[NL80211_STA_INFO_MAX + 1];
    static struct nla_policy stats_policy[NL80211_STA_INFO_MAX + 1] = {
        [NL80211_STA_INFO_INACTIVE_TIME] = { .type = NLA_U32 },
        [NL80211_STA_INFO_RX_BYTES] = { .type = NLA_U32 },
        [NL80211_STA_INFO_TX_BYTES] = { .type = NLA_U32 },
        [NL80211_STA_INFO_RX_PACKETS] = { .type = NLA_U32 },
        [NL80211_STA_INFO_TX_PACKETS] = { .type = NLA_U32 },
        [NL80211_STA_INFO_SIGNAL] = { .type = NLA_U8 },
        [NL80211_STA_INFO_TX_BITRATE] = { .type = NLA_NESTED },
        [NL80211_STA_INFO_RX_BITRATE] = { .type = NLA_NESTED },
        [NL80211_STA_INFO_LLID] = { .type = NLA_U16 },
        [NL80211_STA_INFO_PLID] = { .type = NLA_U16 },
        [NL80211_STA_INFO_PLINK_STATE] = { .type = NLA_U8 },
        [NL80211_STA_INFO_TX_RETRIES] = { .type = NLA_U32 },
        [NL80211_STA_INFO_TX_FAILED] = { .type = NLA_U32 },
        [NL80211_STA_INFO_STA_FLAGS] = { .minlen = sizeof(struct nl80211_sta_flag_update) },
        [NL80211_STA_INFO_SIGNAL] = { .type = NLA_NESTED },
        [NL80211_STA_INFO_SIGNAL_AVG] = { .type = NLA_NESTED },
    };

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
          genlmsg_attrlen(gnlh, 0), NULL);



    if(!tb[NL80211_ATTR_STA_INFO]) {
        fprintf(stderr, "sta stats missing!\n");
        return NL_SKIP;
    }

    if(nla_parse_nested(sinfo, NL80211_STA_INFO_MAX,
                 tb[NL80211_ATTR_STA_INFO],
                 stats_policy)) {
        fprintf(stderr, "failed to parse nested attributes!\n");
        return NL_SKIP;
    }

    memcpy(mac, nla_data(tb[NL80211_ATTR_MAC]), ETH_ALEN);
    if_indextoname(nla_get_u32(tb[NL80211_ATTR_IFINDEX]), dev);
    log_debug("received data : parsing it");
    if((*all_ifaces)) {
        struct cnl80211_station_interface *iter = NULL, *prev = NULL;
        iter = *all_ifaces;
        while(iface == NULL) {
            if(iter == NULL) {
                iface = (struct cnl80211_station_interface *) calloc(1, sizeof(struct cnl80211_station_interface));
                prev->next = iface;
                strncpy(iface->interface, dev, 20);
                break;
            }
            if(strncmp(iter->interface, dev, 20) == 0) {
                iface = iter;
            }
            prev = iter;
            iter = iter->next;
        }
    } else {
        iface = (struct cnl80211_station_interface *) calloc(1, sizeof(struct cnl80211_station_interface));
        strncpy(iface->interface, dev, 20);
        *all_ifaces = iface;
    }
    log_debug("scanning for our station ...");
    if(iface->stations) {
        struct cnl80211_station *iter = NULL, *prev = NULL;
        iter = iface->stations;
        while(station == NULL) {
            log_debug("create sta: while start ");
            if(iter == NULL) {
                log_debug("alloc new station");
                station = (struct cnl80211_station *) calloc(1, sizeof(struct cnl80211_station));
                prev->next = station;
                memcpy(station->mac, mac, ETH_ALEN);
                iface->num_stations += 1;
                break;
            }
            log_debug("check mac");
            if(memcmp(mac, iter->mac, ETH_ALEN) == 0) {
                log_debug("found station");
                station = iter;
            }
            log_debug("before iter replacement");
            prev = iter;
            iter = iter->next;
        }
    } else {
        log_debug("create new stationlist");
        station = (struct cnl80211_station *) calloc(1, sizeof(struct cnl80211_station));
        memcpy(station->mac, mac, ETH_ALEN);
        iface->stations = station;
        iface->num_stations = 1;
    }
    log_debug("parsing data");
    if (nla_parse_nested(sinfo, NL80211_STA_INFO_MAX,
                 tb[NL80211_ATTR_STA_INFO],
                 stats_policy)) {
        fprintf(stderr, "failed to parse nested attributes!\n");
        return NL_SKIP;
    }
    log_debug("got station and iface");
    if(sinfo[NL80211_STA_INFO_INACTIVE_TIME])
        station->inactive_time = nla_get_u32(sinfo[NL80211_STA_INFO_INACTIVE_TIME]);
    if(sinfo[NL80211_STA_INFO_CONNECTED_TIME])
        station->connection_time = nla_get_u32(sinfo[NL80211_STA_INFO_CONNECTED_TIME]);

    if(sinfo[NL80211_STA_INFO_RX_BYTES])
        station->rx_bytes = nla_get_u32(sinfo[NL80211_STA_INFO_RX_BYTES]);
    if(sinfo[NL80211_STA_INFO_TX_BYTES])
        station->tx_bytes = nla_get_u32(sinfo[NL80211_STA_INFO_TX_BYTES]);
    if(sinfo[NL80211_STA_INFO_RX_PACKETS])
        station->rx_pkg = nla_get_u32(sinfo[NL80211_STA_INFO_RX_PACKETS]);
    if(sinfo[NL80211_STA_INFO_TX_PACKETS])
        station->tx_pkg = nla_get_u32(sinfo[NL80211_STA_INFO_TX_PACKETS]);

    if(sinfo[NL80211_STA_INFO_TX_RETRIES])
        station->tx_retries = nla_get_u32(sinfo[NL80211_STA_INFO_TX_RETRIES]);
    if(sinfo[NL80211_STA_INFO_TX_FAILED])
        station->tx_failed = nla_get_u32(sinfo[NL80211_STA_INFO_TX_FAILED]);

    if(sinfo[NL80211_STA_INFO_STA_FLAGS])
        station->mask = nla_get_u32(sinfo[NL80211_STA_INFO_STA_FLAGS]);
    if(sinfo[NL80211_STA_INFO_BEACON_LOSS])
        station->beacon_loss = nla_get_u32(sinfo[NL80211_STA_INFO_BEACON_LOSS]);

    return NL_SKIP;
}

static int cnl80211_read_station_dump(const char *iface) {
    int devidx = if_nametoindex(iface);
    struct nl_cb *cb = ctx->cb;
    struct nl_msg *msg = nlmsg_alloc();
    int err = 0;

    if (!msg) {
	    fprintf(stderr, "failed to allocate netlink message\n");
	    return 2;
    }

    nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, station_dump_handler, &(ctx->station_iface));

    genlmsg_put(msg, 0, 0, ctx->family, 0,
		    NLM_F_DUMP, NL80211_CMD_GET_STATION, 0);

    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devidx);


    err = nl_send_auto_complete((ctx->sock), msg);
    if (err < 0) {
	    fprintf(stderr, "send_auto\n");
        nlmsg_free(msg);
    }

    nlmsg_free(msg);
    ctx->stopReceiving = 1;

    while(ctx->stopReceiving) {
        err = nl_recvmsgs_default(ctx->sock);
    }

    return NL_SKIP;

  nla_put_failure:
//    nlmsg_free(msg);

    return NL_SKIP;

}

static void clear_sta_ifaces() {
    struct cnl80211_station_interface *iface, *old_iface;
    struct cnl80211_station *sta, *old_sta;
    
    iface = ctx->station_iface;
    while(iface != NULL) {
        sta = iface->stations;
        while(sta != NULL) {
            old_sta = sta;
            sta = sta->next;
            free(old_sta);
        }
        old_iface = iface;
        iface = iface->next;
        free(old_iface);
    }
    ctx->station_iface = NULL;
    log_debug("reset station_dump data");
}

static void cnl80211_submit(char *plugin_instance, char *type_inst, char *type, double value) {
    value_t values[1];
    value_list_t vl = VALUE_LIST_INIT;
    char *fuckup = plugin_instance;
    if(plugin_instance == '\0') {
        vl.values_len = 2;
    }

    values[0].gauge = value;

    vl.values = values;
    vl.values_len = 1;
    sstrncpy (vl.host, hostname_g, sizeof (vl.host));
    sstrncpy (vl.plugin, "nl80211", sizeof (vl.plugin));
    sstrncpy (vl.plugin_instance, plugin_instance, sizeof (vl.plugin_instance));
    sstrncpy (vl.type, type, sizeof (vl.type));
    sstrncpy (vl.type_instance, type_inst, sizeof (vl.type_instance));

    plugin_dispatch_values (&vl);
}

static int cnl80211_read() {

    struct cnl80211_interface *iface = ctx->interfaces;
    struct cnl80211_station_interface *sta_iface = NULL;
    struct cnl80211_station *sta = NULL;
    char mac[20];
    char identified[60];

    clear_sta_ifaces();
    log_debug("asking nl80211 to dump data");
    while(iface != NULL) {
        cnl80211_read_station_dump(iface->interface);
        iface = iface->next;
    }
    
    sta_iface = ctx->station_iface;
    log_debug("within sta_iface");
    if(sta_iface) {
        while(sta_iface != NULL) {
            int i = 0;
            cnl80211_submit(sta_iface->interface, "", "stations", sta_iface->num_stations);
            sta = sta_iface->stations;
            while(sta != NULL) {
                log_debug("within sta");
                value_t values[11];
                value_list_t vl = VALUE_LIST_INIT;
                vl.values_len = 11;
                vl.values = values;
                mac_addr_n2a(mac, sta->mac);
                sprintf(identified, "%s_%s", sta_iface, mac);
                //cnl80211_submit(sta_iface->interface, identified, "beacon_loss", sta->beacon_loss);
                values[0].gauge = sta->connection_time;
                values[1].gauge = sta->inactive_time;
                values[2].gauge = sta->rx_bytes;
                values[3].gauge = sta->tx_bytes;
                values[4].gauge = sta->rx_pkg;
                values[5].gauge = sta->tx_pkg;
                values[6].gauge = sta->tx_retries;
                values[7].gauge = sta->tx_failed;
                values[8].gauge = sta->signal;
                values[9].gauge = sta->mask;
                values[10].gauge = sta->beacon_loss;

                sstrncpy (vl.host, hostname_g, sizeof (vl.host));
                sstrncpy (vl.plugin, "nl80211", sizeof (vl.plugin));
                sstrncpy (vl.plugin_instance, sta_iface->interface, sizeof (vl.plugin_instance));
                sstrncpy (vl.type, "nl_station", sizeof (vl.type));
                sstrncpy (vl.type_instance, mac, sizeof (vl.type_instance));
                plugin_dispatch_values (&vl);

                sta = sta->next;
            }
            sta_iface = sta_iface->next;
        }
    }
    // get survey input
    // get stations
    // get 
    return 0;
}
/*
struct parse_nl_cb_args {
    struct cnl80211_ctx *ctx;
};

static int survey_handler(struct nl_msg *msg, void*arg) {

    static struct nla_policy survey_policy[NL80211_SURVEY_INFO_MAX + 1] = {
        [NL80211_SURVEY_INFO_FREQUENCY] = { .type = NLA_U32 },
        [NL80211_SURVEY_INFO_NOISE] = { .type = NLA_U8 },
    };

    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    char dev[20];
    int ret = 0;

    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct nlattr *tb[NL80211_ATTR_MAX];
    struct nlattr *sinfo[NL80211_SURVEY_INFO_MAX + 1];

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
          genlmsg_attrlen(gnlh, 0), NULL);

    if_indextoname(nla_get_u32(tb[NL80211_ATTR_IFINDEX]), dev);
    ret = nla_parse_nested(sinfo, NL80211_SURVEY_INFO_MAX,
                     tb[NL80211_ATTR_SURVEY_INFO],
                     survey_policy);
    if (!tb[NL80211_ATTR_SURVEY_INFO]) {
        fprintf(stderr, "survey data missing!\n");
        return NL_SKIP;
    }

    if (nla_parse_nested(sinfo, NL80211_SURVEY_INFO_MAX,
                 tb[NL80211_ATTR_SURVEY_INFO],
                 survey_policy)) {
        fprintf(stderr, "failed to parse nested attributes!\n");
        return NL_SKIP;
    }

    return NL_SKIP;
}
static int parse_nl_cb(struct nl_msg *msg, void *arg) {
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    char dev[20];
    int ret = 0;

    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct nlattr *tb[NL80211_ATTR_MAX];
    struct nlattr *sinfo[NL80211_SURVEY_INFO_MAX + 1];

    static struct nla_policy survey_policy[NL80211_SURVEY_INFO_MAX + 1] = {
        [NL80211_SURVEY_INFO_FREQUENCY] = { .type = NLA_U32 },
        [NL80211_SURVEY_INFO_NOISE] = { .type = NLA_U8 },
    };
    int foo = genlmsg_attrlen(gnlh, 0);
    if(foo == 0)
        return 0;
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
          genlmsg_attrlen(gnlh, 0), NULL);

   // if_indextoname(nla_get_u32(tb[NL80211_ATTR_IFINDEX]), dev);
    ret = nla_parse_nested(sinfo, NL80211_SURVEY_INFO_MAX,
                     tb[NL80211_ATTR_SURVEY_INFO],
                     survey_policy);

    //struct parse_nl_cb_args *args = (struct parse_nl_cb_args *) arg;
    printf("Callback called %i\n", ret);

    return 0;
}
*/

static int cnl80211_init() {
    int family;
    struct nl_msg *msg;
    int ret = 0;
    //memset(&ctx, 0, sizeof(struct cnl80211_ctx));
    if(ctx == NULL) {
        ctx = (struct cnl80211_ctx *) calloc(1, sizeof(struct cnl80211_ctx));
    }

    /* init netlink */
    ctx->sock = nl_socket_alloc();
    if(!ctx->sock) {
        // TODO logging
        printf("Alloc failed\n");
        goto error_handle;
    }
    ret = genl_connect(ctx->sock);
    if(ret != 0) {
        // TODO logging
        printf("connect failed %i\n", ret);
        goto error_handle;
    }
    ctx->family = genl_ctrl_resolve(ctx->sock, "nl80211");
    if(ctx->family < 0) {
        goto error_handle;
    }

    ctx->cb = nl_cb_alloc(NL_CB_DEFAULT);

    if (!ctx->cb) {
        fprintf(stderr, "failed to allocate netlink callback\n");
        goto error_handle;
    }

    nl_socket_set_cb(ctx->sock, ctx->cb);
    nl_cb_err(ctx->cb, NL_CB_VERBOSE, parse_err_nl_cb, NULL);
    nl_cb_set(ctx->cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, NULL);
    nl_cb_set(ctx->cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, NULL);
    log_info("init done");
    return 0;

  error_handle:
    nl_socket_free(ctx->sock);
    return -1;
} 

static int cnl80211_shutdown() {
    struct cnl80211_interface *iter = ctx->interfaces;
    struct cnl80211_interface *old;
    while(iter != 0) {
        old = iter;
        iter = iter->next;
        free(old);
    }   
    if(ctx->sock) {
        nl_socket_free(ctx->sock);
    }
    return 0;
}


void module_register (void)
{
    plugin_register_config ("nl80211", cnl80211_config, config_keys,
        config_keys_num);
    plugin_register_init("nl80211", cnl80211_init);
    plugin_register_read ("nl80211", cnl80211_read);
    plugin_register_shutdown ("nl80211", cnl80211_shutdown);
} /* void module_register */


/*
int main() {
    struct nl_msg *msg;
    int err;

    if(cnl80211_init() == -1) {
        return 6;
    }
    //cnl80211_config(NULL, NULL);

    msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "failed to allocate netlink message\n");
        return 2;
    }
    ctx->cb = nl_cb_alloc(NL_CB_DEFAULT);

    if (!ctx->cb) {
        fprintf(stderr, "failed to allocate netlink callback\n");
        goto nla_put_failure;
    }

    genlmsg_put(msg, 0, 0, ctx->family, 0,
            NLM_F_DUMP, NL80211_CMD_GET_SURVEY, 0);
    //                                                                    ,version = 0
    //genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, ctx->family, 0, NLM_F_DUMP, NL80211_CMD_GET_SURVEY, 0);
    int devidx = if_nametoindex("wlan0");
    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devidx);


//    err = nl_send_auto_complete(ctx->sock, msg);
//    if (err < 0) {
//        fprintf(stderr, "send_auto\n");
//        goto nla_put_failure;
//    }
    nl_socket_set_cb(ctx->sock, ctx->cb);
    nl_cb_err(ctx->cb, NL_CB_VERBOSE, parse_err_nl_cb, &err);
    nl_cb_set(ctx->cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
    nl_cb_set(ctx->cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);
    nl_cb_set(ctx->cb, NL_CB_VALID, NL_CB_CUSTOM, survey_handler, NULL);
    //nl_cb_set(cb, NL_CB_, NL_CB_CUSTOM, parse_nl_cb, &err);

    cnl80211_read_station_dump("wlan0");


    // Prepare socket to receive the answer by specifying the callback
        // function to be called for valid messages.
    //nl_socket_modify_cb(ctx->sock, NL_CB_VALID, NL_CB_CUSTOM, parse_nl_cb, NULL);

    // Wait for the answer and receive it
    int ret = 0;
    ret = nl_recvmsgs_default(ctx->sock);
    // Free message
    nlmsg_free(msg);
    nl80211_shutdown();
    return 77;

 nla_put_failure:
    nlmsg_free(msg);
    nl80211_shutdown();
    return 2;
}
*/
