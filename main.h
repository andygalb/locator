struct nl80211_state {
	struct nl_sock *nl_sock;
	int nl80211_id;
};


static int nl80211_init(struct nl80211_state *state);
static void nl80211_cleanup(struct nl80211_state *state);

static int __handle_cmd(struct nl80211_state *state);
