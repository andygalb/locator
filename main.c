#include <stdio.h>
#include <stdlib.h>
#include <errno.h>


#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>

#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/socket.h>
//#include "nl80211.h>"
#include "main.h"


int main(int argc, char **argv)
{
	struct nl80211_state nlstate;
	int err;
//	const struct cmd *cmd = NULL;


	err = nl80211_init(&nlstate);

	if (err) return 1;

	//	err = __handle_cmd(&nlstate, II_WDEV, argc, argv, &cmd);

	nl80211_cleanup(&nlstate);

	return err;
}


static int nl80211_init(struct nl80211_state *state)
{
	int err;

	nl_socket_alloc();
	state->nl_sock = nl_socket_alloc();
	if (!state->nl_sock) {
		fprintf(stderr, "Failed to allocate netlink socket.\n");
		return -ENOMEM;
	}

	if (genl_connect(state->nl_sock)) {
		fprintf(stderr, "Failed to connect to generic netlink.\n");
		err = -ENOLINK;
		goto out_handle_destroy;
	}

	nl_socket_set_buffer_size(state->nl_sock, 8192, 8192);

	/* try to set NETLINK_EXT_ACK to 1, ignoring errors */
	err = 1;
	setsockopt(nl_socket_get_fd(state->nl_sock), SOL_NETLINK,
		   NETLINK_EXT_ACK, &err, sizeof(err));

	state->nl80211_id = genl_ctrl_resolve(state->nl_sock, "nl80211");
	if (state->nl80211_id < 0) {
		fprintf(stderr, "nl80211 not found.\n");
		err = -ENOENT;
		goto out_handle_destroy;
	}

	return 0;

 out_handle_destroy:
	nl_socket_free(state->nl_sock);
	return err;
}

static void nl80211_cleanup(struct nl80211_state *state)
{
	nl_socket_free(state->nl_sock);
}

/*static int __handle_cmd(struct nl80211_state *state, enum id_input idby,
			int argc, char **argv, const struct cmd **cmdout)
{
	const struct cmd *cmd, *match = NULL, *sectcmd;
	struct nl_cb *cb;
	struct nl_cb *s_cb;
	struct nl_msg *msg;
	signed long long devidx = 0;
	int err, o_argc, i;
	const char *command, *section;
	char *tmp, **o_argv;
	enum command_identify_by command_idby = CIB_NONE;


		command_idby = CIB_WDEV;
		devidx = strtoll(*argv, &tmp, 0);
		if (*tmp != '\0')
			return 1;


	if (devidx < 0)
		return -errno;



	msg = nlmsg_alloc();

	if (!msg) {
		fprintf(stderr, "failed to allocate netlink message\n");
		return 2;
	}

	cb = nl_cb_alloc(iw_debug ? NL_CB_DEBUG : NL_CB_DEFAULT);
	s_cb = nl_cb_alloc(iw_debug ? NL_CB_DEBUG : NL_CB_DEFAULT);
	if (!cb || !s_cb) {
		fprintf(stderr, "failed to allocate netlink callbacks\n");
		err = 2;
		goto out;
	}

	genlmsg_put(msg, 0, 0, state->nl80211_id, 0,
		    cmd->nl_msg_flags, cmd->cmd, 0);

		NLA_PUT_U64(msg, NL80211_ATTR_WDEV, devidx);


	nl_socket_set_cb(state->nl_sock, s_cb);

	err = nl_send_auto_complete(state->nl_sock, msg);

	if (err < 0)
		goto out;

	err = 1;

	nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);
	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_handler, NULL);

	while (err > 0)
		nl_recvmsgs(state->nl_sock, cb);

 out:
	nl_cb_put(cb);
	nl_cb_put(s_cb);
	nlmsg_free(msg);
	return err;

 nla_put_failure:
	fprintf(stderr, "building message failed\n");
	return 2;
}
*/
