/*
 * Copyright (c) 2026      Nanook Consulting  All rights reserved.
 * $COPYRIGHT$
 *
 * Additional copyrights may follow
 *
 * $HEADER$
 */

/* A tool, launcher, scheduler or server of this release and a server on
 * another host prove who they are to each other, the server first - see
 * "Between hosts" in ptl_base_handshake.h. This file holds what both ends
 * share: which way a connect goes, the bytes both credentials are bound
 * to, and whether a server that proved who it is may be talked to. The
 * tool's half of the exchange is in ptl_base_fns.c, beside the local
 * socket's, and the server's in ptl_base_connection_hdlr.c. */

#include "src/include/pmix_config.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "src/include/pmix_globals.h"
#include "src/util/pmix_net.h"
#include "src/util/pmix_output.h"
#include "src/util/pmix_show_help.h"

#include "src/mca/ptl/base/base.h"
#include "src/mca/ptl/base/ptl_base_handshake.h"

bool pmix_ptl_base_test_remote = false;

/* what a bound credential carries: a label, whose it is, the tool's
 * nonce and the server's, then the server's choice */
#define AUTH_LABEL     "pmix-ra2"
#define AUTH_LABEL_LEN 8
#define AUTH_BIND_LEN  (AUTH_LABEL_LEN + 1 + 2 * PMIX_PTL_AUTH_NONCE_LEN)

pmix_status_t pmix_ptl_base_auth_bind(bool server, const unsigned char *tool,
                                      const unsigned char *srv, const char *choice,
                                      size_t choicelen, pmix_byte_object_t *bind)
{
    unsigned char *b;

    PMIX_BYTE_OBJECT_CONSTRUCT(bind);
    if (NULL == tool || NULL == srv || (NULL == choice && 0 < choicelen) ||
        PMIX_PTL_CHOICE_MAX < choicelen) {
        return PMIX_ERR_BAD_PARAM;
    }
    b = (unsigned char *) malloc(AUTH_BIND_LEN + choicelen);
    if (NULL == b) {
        return PMIX_ERR_NOMEM;
    }
    memcpy(b, AUTH_LABEL, AUTH_LABEL_LEN);
    b[AUTH_LABEL_LEN] = server ? 'S' : 'T';
    memcpy(b + AUTH_LABEL_LEN + 1, tool, PMIX_PTL_AUTH_NONCE_LEN);
    memcpy(b + AUTH_LABEL_LEN + 1 + PMIX_PTL_AUTH_NONCE_LEN, srv, PMIX_PTL_AUTH_NONCE_LEN);
    if (0 < choicelen) {
        memcpy(b + AUTH_BIND_LEN, choice, choicelen);
    }
    bind->bytes = (char *) b;
    bind->size = AUTH_BIND_LEN + choicelen;
    return PMIX_SUCCESS;
}

#if PMIX_ENABLE_REMOTE_TOOLS
/* Only a process that is not a client may reach a server on another host:
 * a client's server is the one on its own host that registered it */
static bool may_connect_remote(void)
{
    if (PMIX_PEER_IS_TOOL(pmix_globals.mypeer) ||
        PMIX_PEER_IS_LAUNCHER(pmix_globals.mypeer) ||
        PMIX_PEER_IS_SCHEDULER(pmix_globals.mypeer) ||
        PMIX_PEER_IS_SERVER(pmix_globals.mypeer)) {
        return true;
    }
    return false;
}
#endif

/* Whether an address is this host's, for a process deciding which way to
 * connect - see local_addr in ptl_base_fns.c */
static bool addr_local(const struct sockaddr_storage *addr)
{
    return pmix_ptl_base_local_addr(addr);
}

pmix_status_t pmix_ptl_base_server_route(const struct sockaddr_storage *addr,
                                         const pmix_ptl_module_t *transport,
                                         const char *uri, bool *remote)
{
    *remote = false;
    /* the local transport reaches only this host */
    if (NULL != transport && NULL != transport->peer_identity) {
        return PMIX_SUCCESS;
    }
    if (addr_local(addr)) {
#if !PMIX_ENABLE_LEGACY_SERVERS
        /* only a server of an earlier release is reached over TCP on this
         * host - and this PMIx was built without support for those */
        pmix_show_help("help-ptl-base.txt", "legacy-servers-tcp", true, pmix_globals.hostname,
                       (NULL == uri) ? "(the address given)" : uri);
        return PMIX_ERR_NOT_SUPPORTED;
#else
        PMIX_HIDE_UNUSED_PARAMS(uri);
        return PMIX_SUCCESS;
#endif
    }
#if PMIX_ENABLE_REMOTE_TOOLS
    if (may_connect_remote()) {
        *remote = true;
        return PMIX_SUCCESS;
    }
    pmix_show_help("help-ptl-base.txt", "remote-not-tool", true, pmix_globals.hostname,
                   (NULL == uri) ? "(the address given)" : uri);
    return PMIX_ERR_UNREACH;
#else
    PMIX_HIDE_UNUSED_PARAMS(uri);
    pmix_show_help("help-ptl-base.txt", "server-not-local", true, pmix_globals.hostname,
                   pmix_net_get_hostname((struct sockaddr *) addr),
                   pmix_net_get_port((struct sockaddr *) addr));
    return PMIX_ERR_UNREACH;
#endif
}

bool pmix_ptl_base_uri_is_remote(const char *uri)
{
#if PMIX_ENABLE_REMOTE_TOOLS
    struct sockaddr_storage addr;
    pmix_ptl_module_t *transport = NULL;
    size_t len;

    if (NULL == uri || !may_connect_remote() ||
        PMIX_SUCCESS != pmix_ptl_base_uri_to_addr(uri, &addr, &len, &transport) ||
        (NULL != transport && NULL != transport->peer_identity)) {
        return false;
    }
    return !addr_local(&addr);
#else
    PMIX_HIDE_UNUSED_PARAMS(uri);
    return false;
#endif
}

pmix_status_t pmix_ptl_base_remote_server_ok(uid_t kuid, gid_t kgid, bool given, uid_t uid,
                                             gid_t gid)
{
    char want[160];
    size_t n;
    bool ok;

    if (given) {
        /* the server that started us said who it is */
        ok = (kuid == uid && kgid == gid);
    } else {
        ok = (kuid == geteuid() || 0 == kuid);
        for (n = 0; !ok && n < pmix_ptl_base.naccess_uids; n++) {
            ok = (kuid == pmix_ptl_base.access_uids[n]);
        }
        for (n = 0; !ok && n < pmix_ptl_base.naccess_gids; n++) {
            ok = (kgid == pmix_ptl_base.access_gids[n]);
        }
    }
    if (ok) {
        return PMIX_SUCCESS;
    }
    if (given) {
        snprintf(want, sizeof(want), "uid %lu gid %lu, as the server that started this "
                 "process said", (unsigned long) uid, (unsigned long) gid);
    } else {
        snprintf(want, sizeof(want), "this process's own user, root, or one "
                 "pmix_ptl_base_server_access allows");
    }
    pmix_show_help("help-ptl-base.txt", "server-identity-remote", true, pmix_globals.hostname,
                   (unsigned long) kuid, (unsigned long) kgid, want);
    return PMIX_ERR_INVALID_CRED;
}
