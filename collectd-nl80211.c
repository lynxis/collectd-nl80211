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
#define log_info(...) INFO ("nl80211: " __VA_ARGS__)
#define log_debug(...) DEBUG ("nl80211: " __VA_ARGS__)

#define DEFAULT_MAX_STATION_DUMPS 50
// there should be max 38 channels - 14 2.4ghz, 24 5ghz
#define DEFAULT_MAX_CHANNEL_SURVEYS 38
#define MAX_DEVICE_NAME_LENGTH 32

static const char *config_keys[] =
{
    "interface",
    "max_station_dumps",
    "max_survey_channels",
    NULL
};

static int config_keys_num = 3;

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
    int8_t signal;
    int8_t signal_avg;
    uint16_t mask;
};

struct cnl80211_station_interface {
    int num_stations;
    struct cnl80211_station *stations;
};

struct cnl80211_survey_channel {
    uint32_t freq;
    int8_t noise;
    int8_t inuse;
    uint64_t active;
    uint64_t busy;
    uint64_t extbusy;
    uint64_t transmit;
    uint64_t recv;
};

struct cnl80211_survey_interface {
    short channels;
    struct cnl80211_survey_channel *survey_channel;
};


struct cnl80211_interface {
    /* while config phase - we only write char interface
     * after config phase we will init everything else, because you can set buffers in config file */
    char *interface;
    struct cnl80211_station_interface station_dump;
    struct cnl80211_survey_interface survey_dumps;
    struct cnl80211_interface *next;
};

struct cnl80211_ctx {
    struct nl_sock *sock;
    int family;
    struct cnl80211_interface *interfaces;
    int stopReceiving; // used to stop receiving loop
    struct nl_cb *cb;
    int max_stations;
    int max_survey_dumps;
};



static int8_t get_signal_from_chain(struct nlattr *attr_list);
static void alloc_interface_values();


static struct cnl80211_ctx ctx;


static void add_interface(const char *iface) {
    struct cnl80211_interface **iter = &(ctx.interfaces);

    while(*iter != NULL) {
        iter = &((*iter)->next);
    }
    (*iter) = (struct cnl80211_interface *) calloc(1, sizeof(struct cnl80211_interface));
    (*iter)->interface = strdup(iface);
}

static void alloc_interface_values() {
    struct cnl80211_interface *iface = ctx.interfaces;

    while(iface != NULL) {
        // TODO checks for failed callocs ...
        iface->station_dump.stations = (struct cnl80211_station_interface *) calloc(ctx.max_stations, sizeof(struct cnl80211_station_interface));
        iface->station_dump.num_stations = 0;
        iface->survey_dumps.survey_channel = (struct cnl80211_survey_channel *) calloc(ctx.max_survey_dumps, sizeof(struct cnl80211_survey_channel));
        iface->survey_dumps.channels = 0;

        iface = iface->next;
    }
}

static struct cnl80211_interface *get_interface(char *device) {
    struct cnl80211_interface *iface = ctx.interfaces;
    while(iface != NULL) {
        if(strncmp(device, iface->interface, MAX_DEVICE_NAME_LENGTH) == 0)
            return iface;
        iface = iface->next;
    }
    return NULL;
}

static void mac_addr_n2a(char *mac_addr, unsigned char *arg)
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

    char *endptr = NULL;
    if(strcasecmp(key, "interface") == 0) {
        add_interface(value);
    } else if(strcasecmp(key, "max_station_dumps")) {
        ctx.max_stations = strtol(value, &endptr, 10);
        /* we got an partially invalid number */
        if(endptr != NULL)
           return 1;
    } else if(strcasecmp(key, "max_survey_channels")) {
        ctx.max_survey_dumps = strtol(value, &endptr, 10);
        /* we got an partially invalid number */
        if(endptr != NULL)
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
    ctx.stopReceiving = 0;
    return NL_SKIP;
}

static int station_dump_handler(struct nl_msg *msg, void *arg) {
    struct cnl80211_interface *giface = NULL;
    struct cnl80211_station_interface *station_iface = NULL;
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
#ifdef NL80211_STA_INFO_CHAIN_SIGNAL
        [NL80211_STA_INFO_CHAIN_SIGNAL] = { .type = NLA_NESTED },
#endif
#ifdef NL80211_STA_INFO_CHAIN_SIGNAL_AVG
        [NL80211_STA_INFO_CHAIN_SIGNAL_AVG] = { .type = NLA_NESTED },
#endif
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

    log_debug("get interface for it");
    giface = get_interface(dev);
    if(giface == NULL) {
        log_debug("can not find right interface!");
        return NL_SKIP;
    }
    station = &(giface->station_dump.stations[giface->station_dump.num_stations]);
    giface->station_dump.num_stations++;
    memset(station, '\0', sizeof(struct cnl80211_station));

    log_debug("parsing data");
    if (nla_parse_nested(sinfo, NL80211_STA_INFO_MAX,
                 tb[NL80211_ATTR_STA_INFO],
                 stats_policy)) {
        fprintf(stderr, "failed to parse nested attributes!\n");
        return NL_SKIP;
    }
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
#ifdef NL80211_STA_INFO_BEACON_LOSS
    if(sinfo[NL80211_STA_INFO_BEACON_LOSS])
        station->beacon_loss = nla_get_u32(sinfo[NL80211_STA_INFO_BEACON_LOSS]);
#endif
    if(sinfo[NL80211_STA_INFO_SIGNAL])
        station->signal = (int8_t)nla_get_u8(sinfo[NL80211_STA_INFO_SIGNAL]);
#ifdef NL80211_STA_INFO_CHAIN_SIGNAL
    else if(sinfo[NL80211_STA_INFO_CHAIN_SIGNAL])
        station->signal = get_signal_from_chain(sinfo[NL80211_STA_INFO_CHAIN_SIGNAL]);
#endif

    if(sinfo[NL80211_STA_INFO_SIGNAL_AVG])
        station->signal_avg = (int8_t)nla_get_u8(sinfo[NL80211_STA_INFO_SIGNAL_AVG]);
#ifdef NL80211_STA_INFO_CHAIN_SIGNAL_AVG
    else if(sinfo[NL80211_STA_INFO_CHAIN_SIGNAL_AVG])
        station->signal_avg = get_signal_from_chain(sinfo[NL80211_STA_INFO_CHAIN_SIGNAL_AVG]);
#endif

    return NL_SKIP;
}

static int survey_dump_handler(struct nl_msg *msg, void*arg) {
    struct cnl80211_interface *giface = NULL;
    struct cnl80211_station_interface *iface = NULL;
    struct cnl80211_survey_channel *survey = NULL;

    static struct nla_policy survey_policy[NL80211_SURVEY_INFO_MAX + 1] = {
        [NL80211_SURVEY_INFO_FREQUENCY] = { .type = NLA_U32 },
        [NL80211_SURVEY_INFO_NOISE] = { .type = NLA_U8 },
    };
    
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    char dev[20];
    int ret = 0;
    uint32_t freq;

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
        return NL_STOP;
    }

    if (nla_parse_nested(sinfo, NL80211_SURVEY_INFO_MAX,
                 tb[NL80211_ATTR_SURVEY_INFO],
                 survey_policy)) {
        fprintf(stderr, "failed to parse nested attributes!\n");
        return NL_STOP;
    }

	if (!sinfo[NL80211_SURVEY_INFO_FREQUENCY]) {
        fprintf(stderr, "survey dump missing frequency!\n");
        return NL_STOP;
    }
	freq = nla_get_u32(sinfo[NL80211_SURVEY_INFO_FREQUENCY]);

    giface = get_interface(dev);
    survey =  &(giface->survey_dumps.survey_channel[giface->survey_dumps.channels]);
    giface->survey_dumps.channels++;
    memset(survey, '\0', sizeof(struct cnl80211_survey_channel));

    survey->freq = freq;
    if (sinfo[NL80211_SURVEY_INFO_IN_USE])
        survey->inuse = 1;
	if (sinfo[NL80211_SURVEY_INFO_NOISE])
		survey->noise = (int8_t)nla_get_u8(sinfo[NL80211_SURVEY_INFO_NOISE]);
	if (sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME])
		survey->active = (unsigned long long)nla_get_u64(sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME]);
	if (sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_BUSY])
		survey->busy = (unsigned long long)nla_get_u64(sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_BUSY]);
	if (sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_EXT_BUSY])
		survey->extbusy = (unsigned long long)nla_get_u64(sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_EXT_BUSY]);
	if (sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_RX])
	    survey->recv = (unsigned long long)nla_get_u64(sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_RX]);
	if (sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_TX])
		survey->transmit = (unsigned long long)nla_get_u64(sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_TX]);

    return NL_OK;
}

static int cnl80211_read_survey_dump(const char *iface) {
    int devidx = if_nametoindex(iface);
    struct nl_cb *cb = ctx.cb;
    struct nl_msg *msg = nlmsg_alloc();
    int err = 0;

    if (!msg) {
	    fprintf(stderr, "failed to allocate netlink message\n");
        return 2;
    }

    /* TODO: check if we just give the interface pointer to the callback */
    nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, survey_dump_handler, NULL);

    genlmsg_put(msg, 0, 0, ctx.family, 0,
            NLM_F_DUMP, NL80211_CMD_GET_SURVEY, 0);

    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devidx);


    err = nl_send_auto_complete((ctx.sock), msg);
    if (err < 0) {
	    fprintf(stderr, "send_auto\n");
        nlmsg_free(msg);
    }

    nlmsg_free(msg);
    ctx.stopReceiving = 1;

    while(ctx.stopReceiving) {
        err = nl_recvmsgs_default(ctx.sock);
    }

    return 0;

  nla_put_failure:
    log_warn("netlink failure when trying to send a nl message");
    nlmsg_free(msg);

    return 0;

}

static int cnl80211_read_station_dump(const char *iface) {
    int devidx = if_nametoindex(iface);
    struct nl_cb *cb = ctx.cb;
    struct nl_msg *msg = nlmsg_alloc();
    int err = 0;

    if (!msg) {
	    fprintf(stderr, "failed to allocate netlink message\n");
        return -2;
    }
    // TODO: put interface arg instead of NULL
    nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, station_dump_handler, NULL);

    genlmsg_put(msg, 0, 0, ctx.family, 0,
		    NLM_F_DUMP, NL80211_CMD_GET_STATION, 0);

    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devidx);


    err = nl_send_auto_complete((ctx.sock), msg);
    if (err < 0) {
	    fprintf(stderr, "send_auto\n");
        nlmsg_free(msg);
    }

    nlmsg_free(msg);
    ctx.stopReceiving = 1;

    while(ctx.stopReceiving) {
        err = nl_recvmsgs_default(ctx.sock);
    }

    return 0;

  nla_put_failure:
    log_warn("netlink failure when trying to send a nl message");
    nlmsg_free(msg);

    return -2;

}

static void clear_ifaces() {
    struct cnl80211_interface *iface;
    log_debug("reset station_dump data");
    while(iface != NULL) {
        iface->station_dump.num_stations = 0;
        iface->survey_dumps.channels = 0;
        iface = iface->next;
    }
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

/* called by collectd every x seconds  (interval) */
static int cnl80211_read() {

    struct cnl80211_interface *iface = ctx.interfaces;
    char mac[20];
    char freq[66];

    clear_ifaces();
    log_debug("asking nl80211 to dump data");
    while(iface != NULL) {
        cnl80211_read_station_dump(iface->interface);
        cnl80211_read_survey_dump(iface->interface);
        iface = iface->next;
    }

    iface = ctx.interfaces;
    while(iface != NULL) {
        int i = 0;
        for(i=0; i < (iface->station_dump.num_stations); i++) {
            struct cnl80211_station *sta = &(iface->station_dump.stations[i]);

            cnl80211_submit(iface->interface, "", "stations", iface->station_dump.num_stations);
            value_t values[12];
            value_list_t vl = VALUE_LIST_INIT;
            vl.values_len = 12;
            vl.values = values;
            mac_addr_n2a(mac, sta->mac);
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
            values[11].gauge = sta->signal_avg;

            sstrncpy (vl.host, hostname_g, sizeof (vl.host));
            sstrncpy (vl.plugin, "nl80211", sizeof (vl.plugin));
            sstrncpy (vl.plugin_instance, iface->interface, sizeof (vl.plugin_instance));
            sstrncpy (vl.type, "nl_station", sizeof (vl.type));
            sstrncpy (vl.type_instance, mac, sizeof (vl.type_instance));
            plugin_dispatch_values (&vl);
        }
        for(i=0 ; i < (iface->survey_dumps.channels); i++) {
            struct cnl80211_survey_channel *survey = &(iface->survey_dumps.survey_channel[i]);
            log_debug("send : survey");

            value_t values[7];
            value_list_t vl = VALUE_LIST_INIT;
            vl.values_len = 7;
            vl.values = values;

            values[0].gauge = survey->noise;
            values[1].gauge = survey->active;
            values[2].gauge = survey->busy;
            values[3].gauge = survey->extbusy;
            values[4].gauge = survey->transmit;
            values[5].gauge = survey->recv;
            values[6].gauge = survey->inuse;

            sprintf(freq, "%u", survey->freq);
            sstrncpy (vl.host, hostname_g, sizeof (vl.host));
            sstrncpy (vl.plugin, "nl80211", sizeof (vl.plugin));
            sstrncpy (vl.plugin_instance, iface->interface, sizeof(vl.plugin_instance));
            sstrncpy (vl.type, "nl_survey", sizeof (vl.type));
            sstrncpy (vl.type_instance, freq, sizeof (vl.type_instance));
            plugin_dispatch_values (&vl);

        }

        iface = iface->next;
    }
    // get survey input
    // get stations
    // get 
    return 0;
}

struct parse_nl_cb_args {
    struct cnl80211_ctx *ctx;
};

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


static int cnl80211_init() {
    int family;
    struct nl_msg *msg;
    int ret = 0;

    alloc_interface_values();

    /* init netlink */
    ctx.sock = nl_socket_alloc();
    if(!ctx.sock) {
        // TODO logging
        printf("Alloc failed\n");
        goto error_handle;
    }
    ret = genl_connect(ctx.sock);
    if(ret != 0) {
        // TODO logging
        printf("connect failed %i\n", ret);
        goto error_handle;
    }
    ctx.family = genl_ctrl_resolve(ctx.sock, "nl80211");
    if(ctx.family < 0) {
        goto error_handle;
    }

    ctx.cb = nl_cb_alloc(NL_CB_DEFAULT);

    if (!ctx.cb) {
        fprintf(stderr, "failed to allocate netlink callback\n");
        goto error_handle;
    }

    nl_socket_set_cb(ctx.sock, ctx.cb);
    nl_cb_err(ctx.cb, NL_CB_VERBOSE, parse_err_nl_cb, NULL);
    nl_cb_set(ctx.cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, NULL);
    nl_cb_set(ctx.cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, NULL);
    log_info("init done");
    return 0;

  error_handle:
    nl_socket_free(ctx.sock);
    return -1;
} 

static int cnl80211_shutdown() {
    struct cnl80211_interface *iter = ctx.interfaces;
    struct cnl80211_interface *old;
    while(iter != 0) {
        old = iter;
        iter = iter->next;
        free(old->interface);
        free(old);
    }   
    if(ctx.sock) {
        nl_socket_free(ctx.sock);
    }
    return 0;
}


void module_register (void)
{
    memset(&ctx, 0, sizeof(struct cnl80211_ctx));
    ctx.max_stations = DEFAULT_MAX_STATION_DUMPS;
    ctx.max_survey_dumps = DEFAULT_MAX_CHANNEL_SURVEYS;

    plugin_register_config ("nl80211", cnl80211_config, config_keys,
        config_keys_num);
    plugin_register_init("nl80211", cnl80211_init);
    plugin_register_read ("nl80211", cnl80211_read);
    plugin_register_shutdown ("nl80211", cnl80211_shutdown);
}

/* 
 * returns the last signal value of nested signal
 */
int8_t get_signal_from_chain(struct nlattr *attr_list)
{
    struct nlattr *attr;
    int rem;
    int8_t signal = 0;

    if (!attr_list)
        return signal;

    nla_for_each_nested(attr, attr_list, rem) {
        /* we want the last argument */
        signal = (int8_t) nla_get_u8(attr);
    }

    return signal;
}

