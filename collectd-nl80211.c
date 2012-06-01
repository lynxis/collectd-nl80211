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

#include <string.h>

struct cnl80211_interface;

struct cnl80211_interface {
    char *interface;
    short ignore;
    struct cnl80211_interface *next;
};

struct cnl80211_ctx {
    struct nl_sock *sock;
    int family;
    struct cnl80211_interface *interfaces;
};

static struct cnl80211_ctx ctx;


static void addInterface(char *iface, short ignore) {
    struct cnl80211_interface **iter = &(ctx.interfaces);

    while(*iter != NULL) {
        iter = &((*iter)->next);
    }
    (*iter) = (struct cnl80211_interface *) calloc(1, sizeof(struct cnl80211_interface));
    (*iter)->interface = strdup(iface);
    (*iter)->ignore = ignore;
}

static int cnl80211_init() {
    int family;
    struct nl_msg *msg;
    int ret = 0;
    memset(&ctx, 0, sizeof(struct cnl80211_ctx));

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
        free(old);
    }   
    if(ctx.sock) {
        nl_socket_free(ctx.sock);
    }
    return 0;
}

static int cnl80211_config (const char *key, const char *value) {
    addInterface("wlan0", 0);
    return 0;
}


static int nl80211_shutdown() {
    return 0;
}

static int cnl80211_read_survey() {
    return 0;
}

static int cnl80211_read() {
    cnl80211_read_survey();
    // get survey input
    // get stations
    // get 
    return 0;
}

struct parse_nl_cb_args {
    struct cnl80211_ctx *ctx;
};


static int survey_handler(struct nl_msg *msg, void*arg) {
    printf("survey handler called\n");
    return 0;
}

static int ack_handler(struct nl_msg *msg, void *arg) {
    printf("Ack received\n");
    return 0;
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

static int parse_err_nl_cb(struct sockaddr_nl *nla, struct nlmsgerr *nlerr, void *arg) {
    printf("CallbackError called");
    return 0;
}

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
    struct nl_cb *cb = nl_cb_alloc(NL_CB_DEFAULT);

    if (!cb) {
	    fprintf(stderr, "failed to allocate netlink callback\n");
	    goto nla_put_failure;
    }

    genlmsg_put(msg, 0, 0, ctx.family, 0,
		    NLM_F_DUMP, NL80211_CMD_GET_SURVEY, 0);
    //                                                                    ,version = 0
    //genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, ctx.family, 0, NLM_F_DUMP, NL80211_CMD_GET_SURVEY, 0);
    int devidx = if_nametoindex("wlan0");
    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devidx);


    nl_socket_set_cb(ctx.sock, cb);

    err = nl_send_auto_complete(ctx.sock, msg);
    if (err < 0) {
	    fprintf(stderr, "send_auto\n");
	    goto nla_put_failure;
    }

    nl_cb_err(cb, NL_CB_VERBOSE, parse_err_nl_cb, &err);
    nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, parse_nl_cb, &err);
    nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);
    nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, survey_handler, NULL);
    //nl_cb_set(cb, NL_CB_, NL_CB_CUSTOM, parse_nl_cb, &err);




    // Prepare socket to receive the answer by specifying the callback
	    // function to be called for valid messages.
    //nl_socket_modify_cb(ctx.sock, NL_CB_VALID, NL_CB_CUSTOM, parse_nl_cb, NULL);

    // Wait for the answer and receive it
    int ret = 0;
    printf("entering while true %i \n", ret);
    while(err > 0) {
        ret = nl_recvmsgs_default(ctx.sock);
        printf("ret nl recv %i\n", ret);
        sleep(1);
    }
        
    // Free message
    nlmsg_free(msg);
    nl80211_shutdown();
    return 77;

 nla_put_failure:
    nlmsg_free(msg);
    nl80211_shutdown();
    return 2;
}
