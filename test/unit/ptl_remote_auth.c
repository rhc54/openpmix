/*
 * Copyright (c) 2026      Nanook Consulting  All rights reserved.
 * $COPYRIGHT$
 *
 * Additional copyrights may follow
 *
 * $HEADER$
 *
 * A tool and a server on different hosts authenticate each other, the
 * server first - see "Between hosts" in
 * src/mca/ptl/base/ptl_base_handshake.h. The tool opens with its offer
 * and a nonce; the server answers with its choice, a nonce of its own and
 * a credential bound to both and to the choice; the tool checks that,
 * and whom it names, and only then sends a credential bound the same way.
 *
 * Both run here, on one host, told to treat every TCP address as another
 * host's (pmix_ptl_base_test_remote), with a PKI made for the test. A tool
 * connects to the server's TCP URI:
 *
 *   - by its blocking connect, and by an event-driven attach: taken - with
 *     ssl, and with munge where a munged is running; and as a launcher
 *   - at an address that does not answer, given the server's real one as
 *     an alternate: taken, by both connects
 *   - with no mechanism that makes a credential for one connection: it
 *     sends nothing, saying so
 *   - to a server that takes no tools: refused
 *   - to a server whose certificate it does not trust, or one for clients
 *     only: it refuses the server
 *   - with a certificate the server does not trust: the server refuses it
 *
 * and a peer speaking the wire directly is refused when its opening names
 * a client, or offers no mechanism that makes a credential for one
 * connection, or when its credential is bound to another connection, is
 * made as a server's, or proves another user than its opening named.
 *
 * Built only where psec/ssl is built against a real OpenSSL; it skips in
 * a build without remote tools.
 */

#include "src/include/pmix_config.h"

#include "include/pmix.h"
#include "include/pmix_server.h"
#include "include/pmix_tool.h"
#include "src/include/pmix_globals.h"
#include "src/mca/psec/base/base.h"
#include "src/mca/ptl/base/base.h"
#include "src/mca/ptl/base/ptl_base_handshake.h"
#include "src/util/pmix_error.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ssl_test_pki.h"

#define SKIP 77

static int npass = 0;
static int nfail = 0;

static void report(const char *name, int passed, const char *detail)
{
    if (passed) {
        fprintf(stdout, "  PASS: %s\n", name);
        ++npass;
    } else {
        fprintf(stdout, "  FAIL: %s (%s)\n", name, detail);
        ++nfail;
    }
}

static int ntools = 0;

static void tool_connected(pmix_info_t *info, size_t ninfo, pmix_tool_connection_cbfunc_t cbfunc,
                           void *cbdata)
{
    pmix_proc_t proc;
    PMIX_HIDE_UNUSED_PARAMS(info, ninfo);

    PMIX_LOAD_PROCID(&proc, "remoteauth.tool", ntools++);
    cbfunc(PMIX_SUCCESS, &proc, cbdata);
}

static pmix_server_module_t mymodule = {
    .tool_connected = tool_connected
};

/* the PKI's files */
static char cafile[1024], ca2file[1024], bothcert[1024], clientcert[1024], keyfile[1024],
    foreigncert[1024], foreignkey[1024];

static void use_ssl(const char *ca, const char *cert, const char *key)
{
    setenv("PMIX_MCA_psec_ssl_ca_file", ca, 1);
    setenv("PMIX_MCA_psec_ssl_cert_file", cert, 1);
    setenv("PMIX_MCA_psec_ssl_key_file", key, 1);
}

/* ---------------------------------------------------------------- *
 * the server
 * ---------------------------------------------------------------- */

typedef struct {
    bool tools;        // PMIX_SERVER_TOOL_SUPPORT
    const char *cert;  // its certificate; NULL for munge
} srvcfg_t;

/* listen over TCP, say where, and wait to be told to go. Exits 3 when it
 * was to use munge and there is none, 4 when it found no public
 * interface to listen on */
static void run_server(const srvcfg_t *cfg, int urifd, int gofd)
{
    pmix_info_t info[2];
    bool yes = true, tools = cfg->tools;
    char c, buf[2048];
    pmix_status_t rc;

    /* with no certificate of its own to name, the server is to use munge
     * - it has ssl too, so it starts where munge is not built or no munged
     * runs, and says below that munge is not there. The tool names munge */
    use_ssl(cafile, (NULL == cfg->cert) ? bothcert : cfg->cert, keyfile);
    pmix_ptl_base_test_remote = true;
    PMIX_INFO_LOAD(&info[0], PMIX_SERVER_TOOL_SUPPORT, &tools, PMIX_BOOL);
    PMIX_INFO_LOAD(&info[1], PMIX_SERVER_REMOTE_CONNECTIONS, &yes, PMIX_BOOL);
    rc = PMIx_server_init(&mymodule, info, 2);
    if (PMIX_SUCCESS != rc) {
        _exit(4);
    }
    if (NULL == pmix_ptl_base.listener.uri ||
        NULL == strstr(pmix_ptl_base.listener.uri, "tcp")) {
        _exit(2);
    }
    if (NULL == cfg->cert && NULL == pmix_psec_base_assign_module("munge")) {
        PMIx_server_finalize();
        _exit(3);
    }
    snprintf(buf, sizeof(buf), "%s\n", pmix_ptl_base.listener.uri);
    if ((ssize_t) strlen(buf) != write(urifd, buf, strlen(buf))) {
        _exit(2);
    }
    close(urifd);
    if (0 > read(gofd, &c, 1)) {
        _exit(2);
    }
    PMIx_server_finalize();
    _exit(0);
}

typedef struct {
    pid_t pid;
    int go;
    char uri[2048];   // "nspace.rank;tcp4://host:port"
    char addr[2048];  // the part after the ';'
} server_t;

static void stop_server(server_t *srv)
{
    int st;

    if (0 <= srv->go) {
        if (1 != write(srv->go, "x", 1) && 0 < srv->pid) {
            kill(srv->pid, SIGKILL);
        }
        close(srv->go);
        srv->go = -1;
    }
    if (0 < srv->pid) {
        (void) waitpid(srv->pid, &st, 0);
        srv->pid = -1;
    }
}

/* 0 when it is up; SKIP when it was to use munge and there is none, or
 * there is no public interface; 1 otherwise */
static int start_server(server_t *srv, const srvcfg_t *cfg, const char **why)
{
    int urip[2], gop[2], st;
    char buf[2048], *nl, *semi;
    size_t got = 0;
    ssize_t n;

    srv->pid = -1;
    srv->go = -1;
    *why = "the server did not start";
    if (0 != pipe(urip)) {
        return 1;
    }
    if (0 != pipe(gop)) {
        close(urip[0]);
        close(urip[1]);
        return 1;
    }
    fflush(stdout);
    srv->pid = fork();
    if (0 == srv->pid) {
        alarm(120);
        close(urip[0]);
        close(gop[1]);
        run_server(cfg, urip[1], gop[0]);
    }
    close(urip[1]);
    close(gop[0]);
    srv->go = gop[1];
    if (0 > srv->pid) {
        close(urip[0]);
        stop_server(srv);
        return 1;
    }
    while (got < sizeof(buf) - 1 && 0 < (n = read(urip[0], buf + got, sizeof(buf) - 1 - got))) {
        got += (size_t) n;
    }
    close(urip[0]);
    buf[got] = '\0';
    nl = strchr(buf, '\n');
    if (NULL == nl) {
        /* it did not start - and says why in its status */
        if (srv->pid == waitpid(srv->pid, &st, 0) && WIFEXITED(st)) {
            srv->pid = -1;
            if (3 == WEXITSTATUS(st)) {
                *why = "no munged";
                stop_server(srv);
                return SKIP;
            }
            if (4 == WEXITSTATUS(st)) {
                *why = "no public interface to listen on";
                stop_server(srv);
                return SKIP;
            }
        }
        srv->pid = -1;
        stop_server(srv);
        return 1;
    }
    *nl = '\0';
    snprintf(srv->uri, sizeof(srv->uri), "%s", buf);
    semi = strchr(buf, ';');
    snprintf(srv->addr, sizeof(srv->addr), "%s", (NULL == semi) ? buf : semi + 1);
    return 0;
}

/* ---------------------------------------------------------------- *
 * a real tool
 * ---------------------------------------------------------------- */

typedef struct {
    const char *ca;
    const char *cert;
    const char *key;
    const char *mech;    // the mechanisms to have, if not native and ssl
    bool attach;         // connect by an event-driven attach after init
    bool launcher;       // initialize as a launcher
    const char *alt;     // dial this address first, with the server's as an alternate
} tool_t;

/* a tool connecting to the URI; it exits with the status's negation, and
 * what it says on stderr goes to errpath */
static pmix_status_t run_tool(const server_t *srv, const tool_t *t, const char *errpath)
{
    pmix_info_t info[3];
    pmix_proc_t me, server;
    pmix_status_t rc;
    bool flag = true;
    char uri[2048];
    const char *colon;
    size_t n = 0;
    pid_t pid;
    int status, fd;

    fflush(stdout);
    pid = fork();
    if (0 == pid) {
        alarm(120);
        fd = open(errpath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (0 <= fd) {
            dup2(fd, 2);
            close(fd);
        }
        if (NULL != t->mech) {
            setenv("PMIX_MCA_psec", t->mech, 1);
        } else {
            /* ssl, which the tool offers itself to a server on another
             * host - and not munge, which outranks it where a munged
             * runs */
            setenv("PMIX_MCA_psec", "native,ssl", 1);
        }
        use_ssl(t->ca, t->cert, t->key);
        pmix_ptl_base_test_remote = true;
        if (NULL != t->alt) {
            /* the server's identity with an address that does not answer */
            colon = strchr(srv->uri, ';');
            snprintf(uri, sizeof(uri), "%.*s;%s", (int) (colon - srv->uri), srv->uri, t->alt);
        } else {
            snprintf(uri, sizeof(uri), "%s", srv->uri);
        }
        if (t->launcher) {
            PMIX_INFO_LOAD(&info[n], PMIX_LAUNCHER, &flag, PMIX_BOOL);
            ++n;
        }
        if (t->attach) {
            PMIX_INFO_LOAD(&info[n], PMIX_TOOL_DO_NOT_CONNECT, &flag, PMIX_BOOL);
            rc = PMIx_tool_init(&me, info, n + 1);
            if (PMIX_SUCCESS == rc) {
                PMIX_INFO_LOAD(&info[0], PMIX_SERVER_URI, uri, PMIX_STRING);
                n = 1;
                if (NULL != t->alt) {
                    PMIX_INFO_LOAD(&info[1], PMIX_SERVER_ALT_URIS, srv->addr, PMIX_STRING);
                    n = 2;
                }
                rc = PMIx_tool_attach_to_server(&me, &server, info, n);
                PMIx_tool_finalize();
            }
        } else {
            PMIX_INFO_LOAD(&info[n], PMIX_SERVER_URI, uri, PMIX_STRING);
            ++n;
            if (NULL != t->alt) {
                PMIX_INFO_LOAD(&info[n], PMIX_SERVER_ALT_URIS, srv->addr, PMIX_STRING);
                ++n;
            }
            rc = PMIx_tool_init(&me, info, n);
            if (PMIX_SUCCESS == rc) {
                PMIx_tool_finalize();
            }
        }
        _exit((-rc) & 0xff);
    }
    if (0 > pid || pid != waitpid(pid, &status, 0) || !WIFEXITED(status)) {
        return PMIX_ERROR;
    }
    return -(pmix_status_t) WEXITSTATUS(status);
}

/* whether what the tool wrote to stderr says `what` */
static bool said(const char *path, const char *what)
{
    char buf[16384];
    size_t n;
    FILE *fp;

    fp = fopen(path, "r");
    if (NULL == fp) {
        return false;
    }
    n = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    buf[n] = '\0';
    return NULL != strstr(buf, what);
}

/* a tool against a server; `says` is what the tool must say */
static void one_case(const char *name, const srvcfg_t *cfg, const tool_t *t, pmix_status_t want,
                     const char *says, const char *dir)
{
    server_t srv;
    char detail[512], errpath[1024];
    const char *why;
    pmix_status_t rc;
    bool ok;
    int up;

    up = start_server(&srv, cfg, &why);
    if (SKIP == up) {
        fprintf(stdout, "  SKIP: %s (%s)\n", name, why);
        return;
    }
    if (0 != up) {
        report(name, 0, why);
        return;
    }
    snprintf(errpath, sizeof(errpath), "%s/tool.err", dir);
    rc = run_tool(&srv, t, errpath);
    stop_server(&srv);
    ok = (want == rc) && (NULL == says || said(errpath, says));
    snprintf(detail, sizeof(detail), "the tool's connect returned %s, not %s; said \"%s\": %s",
             PMIx_Error_string(rc), PMIx_Error_string(want), (NULL == says) ? "" : says,
             (NULL != says && said(errpath, says)) ? "yes" : "no");
    report(name, ok, detail);
    unlink(errpath);
}

/* ---------------------------------------------------------------- *
 * a peer speaking the wire directly
 * ---------------------------------------------------------------- */

static bool send_all(int sd, const char *buf, size_t len)
{
    ssize_t n;

    while (0 < len) {
        n = send(sd, buf, len, 0);
        if (0 >= n) {
            return false;
        }
        buf += n;
        len -= (size_t) n;
    }
    return true;
}

static bool recv_all(int sd, char *buf, size_t len)
{
    ssize_t n;

    while (0 < len) {
        n = recv(sd, buf, len, 0);
        if (0 >= n) {
            return false;
        }
        buf += n;
        len -= (size_t) n;
    }
    return true;
}

/* the status the server answers with, or 1 if it closed instead */
static int read_status(int sd, pmix_status_t *st)
{
    uint32_t u32;

    if (!recv_all(sd, (char *) &u32, sizeof(u32))) {
        return 1;
    }
    *st = (pmix_status_t) ntohl(u32);
    return 0;
}

static int connect_tcp(const char *addr)
{
    struct sockaddr_in sa;
    char host[256];
    const char *p, *colon;
    int sd;

    if (0 != strncmp(addr, "tcp4://", 7)) {
        return -1;
    }
    p = addr + 7;
    colon = strrchr(p, ':');
    if (NULL == colon || (size_t) (colon - p) >= sizeof(host)) {
        return -1;
    }
    memcpy(host, p, colon - p);
    host[colon - p] = '\0';
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t) atoi(colon + 1));
    if (1 != inet_pton(AF_INET, host, &sa.sin_addr)) {
        return -1;
    }
    sd = socket(AF_INET, SOCK_STREAM, 0);
    if (0 > sd || 0 != connect(sd, (struct sockaddr *) &sa, sizeof(sa))) {
        if (0 <= sd) {
            close(sd);
        }
        return -1;
    }
    return sd;
}

/* append to a growing message */
typedef struct {
    char buf[4096];
    size_t len;
} wire_t;

static void put(wire_t *w, const void *p, size_t n)
{
    memcpy(w->buf + w->len, p, n);
    w->len += n;
}
static void put_str(wire_t *w, const char *s)
{
    put(w, s, strlen(s) + 1);
}
static void put_u8(wire_t *w, uint8_t v)
{
    put(w, &v, 1);
}
static void put_u32(wire_t *w, uint32_t v)
{
    v = htonl(v);
    put(w, &v, sizeof(v));
}
static void put_list(wire_t *w, const char *one)
{
    put_u8(w, 1);
    put_str(w, one);
}

/* frame a payload as the connect-ack is framed: the header, with its
 * length in host order */
static char *frame(const wire_t *w, size_t *out)
{
    pmix_ptl_hdr_t hdr;
    char *msg;

    memset(&hdr, 0, sizeof(hdr));
    hdr.pindex = -1;
    hdr.tag = UINT32_MAX;
    hdr.nbytes = w->len;
    msg = (char *) malloc(sizeof(hdr) + w->len);
    memcpy(msg, &hdr, sizeof(hdr));
    memcpy(msg + sizeof(hdr), w->buf, w->len);
    *out = sizeof(hdr) + w->len;
    return msg;
}

typedef enum {
    RAW_CLIENT,         // the opening names a simple client
    RAW_NO_MECH,        // ...offers only native
    RAW_WRONG_NONCE,    // the credential is bound to another server nonce
    RAW_AS_SERVER,      // ...is made as a server's
    RAW_OTHER_UID,      // ...proves another user than the opening named
    RAW_GOOD            // everything right: the server asks the host
} raw_t;

/* a peer on the wire: the opening, the server's answer, a credential.
 * Exits with the negation of the status the server answers last, or 1 */
static int raw_peer(raw_t kind, const char *addr)
{
    unsigned char tool[PMIX_PTL_AUTH_NONCE_LEN], srv[PMIX_PTL_AUTH_NONCE_LEN];
    char choice[PMIX_PTL_CHOICE_MAX + 1], *msg, *cbuf;
    pmix_byte_object_t bind, cred;
    pmix_psec_module_t *ssl;
    pmix_info_t info;
    pmix_proc_t me;
    pmix_status_t st, rc;
    uint32_t u32, clen;
    bool flag = true;
    size_t len;
    wire_t w;
    int sd;

    /* a library to make credentials with, connected to nothing */
    setenv("PMIX_MCA_psec", "native,ssl", 1);
    use_ssl(cafile, bothcert, keyfile);
    PMIX_INFO_LOAD(&info, PMIX_TOOL_DO_NOT_CONNECT, &flag, PMIX_BOOL);
    if (PMIX_SUCCESS != PMIx_tool_init(&me, &info, 1)) {
        return 1;
    }
    ssl = pmix_psec_base_assign_module("ssl");
    if (NULL == ssl || NULL == ssl->create_bound) {
        return 1;
    }
    sd = connect_tcp(addr);
    if (0 > sd) {
        return 1;
    }
    memset(tool, 7, sizeof(tool));

    /* the opening */
    w.len = 0;
    put_str(&w, "");
    put_u32(&w, 0);
    put_u8(&w, PMIX_REMOTE_TOOL);
    put_str(&w, PMIX_VERSION);
    if (RAW_CLIENT == kind) {
        put_u8(&w, PMIX_SIMPLE_CLIENT);
        put_str(&w, "remoteauth.job");
        put_u32(&w, 0);
    } else {
        put_u8(&w, PMIX_TOOL_NEEDS_ID);
    }
    put_list(&w, (RAW_NO_MECH == kind) ? "native" : "ssl");
    put_list(&w, "v70");
    put_u8(&w, PMIX_BFROP_BUFFER_NON_DESC);
    put_list(&w, "hash");
    put(&w, tool, sizeof(tool));
    put_u32(&w, (RAW_OTHER_UID == kind) ? geteuid() + 1 : geteuid());
    msg = frame(&w, &len);
    if (!send_all(sd, msg, len)) {
        return 1;
    }
    free(msg);

    /* the answer: a status, the choice, the server's nonce and proof */
    if (0 != read_status(sd, &st)) {
        return 1;
    }
    if (PMIX_SUCCESS != st) {
        return (-st) & 0xff;
    }
    if (!recv_all(sd, (char *) &u32, sizeof(u32))) {
        return 1;
    }
    clen = ntohl(u32);
    if (0 == clen || PMIX_PTL_CHOICE_MAX < clen || !recv_all(sd, choice, clen) ||
        !recv_all(sd, (char *) srv, sizeof(srv)) || !recv_all(sd, (char *) &u32, sizeof(u32))) {
        return 1;
    }
    u32 = ntohl(u32);
    cbuf = (char *) malloc(u32);
    if (NULL == cbuf || !recv_all(sd, cbuf, u32)) {
        return 1;
    }
    free(cbuf);

    /* our credential */
    if (RAW_WRONG_NONCE == kind) {
        srv[0] ^= 0xff;
    }
    rc = pmix_ptl_base_auth_bind(RAW_AS_SERVER == kind, tool, srv, choice, clen, &bind);
    if (PMIX_SUCCESS != rc) {
        return 1;
    }
    rc = ssl->create_bound(&bind, RAW_AS_SERVER == kind, geteuid(), &cred);
    PMIX_BYTE_OBJECT_DESTRUCT(&bind);
    if (PMIX_SUCCESS != rc) {
        return 1;
    }
    w.len = 0;
    put_u32(&w, cred.size);
    put(&w, cred.bytes, cred.size);
    PMIX_BYTE_OBJECT_DESTRUCT(&cred);
    msg = frame(&w, &len);
    if (!send_all(sd, msg, len)) {
        return 1;
    }
    free(msg);
    if (0 != read_status(sd, &st)) {
        return 1;
    }
    close(sd);
    return (-st) & 0xff;
}

static void raw_case(const char *name, raw_t kind, pmix_status_t want, const char *dir)
{
    srvcfg_t cfg = {.tools = true, .cert = bothcert};
    server_t srv;
    char detail[256];
    const char *why;
    pid_t pid;
    int up, st;
    PMIX_HIDE_UNUSED_PARAMS(dir);

    up = start_server(&srv, &cfg, &why);
    if (SKIP == up) {
        fprintf(stdout, "  SKIP: %s (%s)\n", name, why);
        return;
    }
    if (0 != up) {
        report(name, 0, why);
        return;
    }
    fflush(stdout);
    pid = fork();
    if (0 == pid) {
        alarm(60);
        _exit(raw_peer(kind, srv.addr));
    }
    if (0 > pid || pid != waitpid(pid, &st, 0) || !WIFEXITED(st)) {
        stop_server(&srv);
        report(name, 0, "the peer did not finish");
        return;
    }
    stop_server(&srv);
    snprintf(detail, sizeof(detail), "the server answered %s, not %s",
             (1 == WEXITSTATUS(st)) ? "nothing it could read"
                                    : PMIx_Error_string(-(pmix_status_t) WEXITSTATUS(st)),
             PMIx_Error_string(want));
    report(name, -(pmix_status_t) WEXITSTATUS(st) == want, detail);
}

int main(void)
{
    char dir[512];
    const char *base = getenv("TMPDIR");
    EVP_PKEY *cakey, *ca2key, *key, *ukey;
    X509 *ca, *ca2, *both, *client, *foreign;
    struct passwd *pw;
    char *pem;
    size_t n;
    tool_t t;
    srvcfg_t cfg = {.tools = true, .cert = NULL};

    fprintf(stdout, "\n=== a tool and a server on different hosts ===\n\n");
#if !PMIX_ENABLE_REMOTE_TOOLS
    fprintf(stdout, "this PMIx takes no tools from other hosts\n");
    return SKIP;
#endif
    pw = getpwuid(geteuid());
    snprintf(dir, sizeof(dir), "%s/pmix-ra-XXXXXX", (NULL == base) ? "/tmp" : base);
    if (NULL == pw || NULL == mkdtemp(dir)) {
        fprintf(stdout, "no passwd entry or scratch directory - skipping\n");
        return SKIP;
    }
    setenv("TMPDIR", dir, 1);
    setenv("PMIX_MCA_mca_base_param_files", "none", 1);
    signal(SIGPIPE, SIG_IGN);
    alarm(900);

    /* the PKI: a CA, and a second nobody here trusts. Every leaf names
     * this user, who runs both ends */
    cakey = gen_key(EVP_PKEY_EC);
    ca2key = gen_key(EVP_PKEY_EC);
    key = gen_key(EVP_PKEY_EC);
    ukey = gen_key(EVP_PKEY_EC);
    if (NULL == cakey || NULL == ca2key || NULL == key || NULL == ukey) {
        fprintf(stdout, "could not make the keys\n");
        return 1;
    }
    ca = make_cert(cakey, "PMIx test root", NULL, NULL, 1, -60, 86400, NULL);
    ca2 = make_cert(ca2key, "Nobody's root", NULL, NULL, 1, -60, 86400, NULL);
    both = make_cert(key, pw->pw_name, ca, cakey, 10, -60, 86400, "clientAuth,serverAuth");
    client = make_cert(key, pw->pw_name, ca, cakey, 11, -60, 86400, "clientAuth");
    foreign = make_cert(ukey, pw->pw_name, ca2, ca2key, 12, -60, 86400,
                          "clientAuth,serverAuth");
    snprintf(cafile, sizeof(cafile), "%s/ca.pem", dir);
    pem = chain_pem(ca, NULL, &n);
    write_file(cafile, pem, n, 0644);
    free(pem);
    snprintf(ca2file, sizeof(ca2file), "%s/ca2.pem", dir);
    pem = chain_pem(ca2, NULL, &n);
    write_file(ca2file, pem, n, 0644);
    free(pem);
    snprintf(bothcert, sizeof(bothcert), "%s/both.pem", dir);
    pem = chain_pem(both, NULL, &n);
    write_file(bothcert, pem, n, 0644);
    free(pem);
    snprintf(clientcert, sizeof(clientcert), "%s/client.pem", dir);
    pem = chain_pem(client, NULL, &n);
    write_file(clientcert, pem, n, 0644);
    free(pem);
    snprintf(keyfile, sizeof(keyfile), "%s/me.key", dir);
    write_key(keyfile, key, 0600);
    snprintf(foreigncert, sizeof(foreigncert), "%s/foreign.pem", dir);
    pem = chain_pem(foreign, NULL, &n);
    write_file(foreigncert, pem, n, 0644);
    free(pem);
    snprintf(foreignkey, sizeof(foreignkey), "%s/foreign.key", dir);
    write_key(foreignkey, ukey, 0600);

    /* ---- taken ---- */
    memset(&t, 0, sizeof(t));
    t.ca = cafile;
    t.cert = bothcert;
    t.key = keyfile;
    cfg.cert = bothcert;
    one_case("a tool and a server that authenticate each other connect", &cfg, &t, PMIX_SUCCESS,
             NULL, dir);
    t.attach = true;
    one_case("...and by an event-driven attach", &cfg, &t, PMIX_SUCCESS, NULL, dir);
    t.attach = false;
    t.launcher = true;
    one_case("...and as a launcher", &cfg, &t, PMIX_SUCCESS, NULL, dir);
    t.launcher = false;
    t.alt = "tcp4://127.0.0.1:1";
    one_case("...at an alternate address when the first does not answer", &cfg, &t,
             PMIX_SUCCESS, NULL, dir);
    t.attach = true;
    one_case("...and by an event-driven attach", &cfg, &t, PMIX_SUCCESS, NULL, dir);
    t.attach = false;
    t.alt = NULL;
    {
        srvcfg_t mcfg = {.tools = true, .cert = NULL};

        t.mech = "munge";
        one_case("...and with munge", &mcfg, &t, PMIX_SUCCESS, NULL, dir);
        t.attach = true;
        one_case("...and with munge, by an event-driven attach", &mcfg, &t, PMIX_SUCCESS, NULL,
                 dir);
        t.attach = false;
        t.mech = NULL;
    }

    /* ---- refused by the tool ---- */
    t.mech = "native";
    one_case("a tool with no mechanism that proves itself across hosts sends nothing", &cfg, &t,
             PMIX_ERR_NOT_SUPPORTED, "has neither as configured", dir);
    t.attach = true;
    one_case("...and by an event-driven attach", &cfg, &t, PMIX_ERR_NOT_SUPPORTED,
             "has neither as configured", dir);
    t.attach = false;
    t.mech = NULL;
    t.ca = ca2file;
    one_case("a tool refuses a server whose certificate it does not trust", &cfg, &t,
             PMIX_ERR_INVALID_CRED, "did not prove who it is", dir);
    t.attach = true;
    one_case("...and by an event-driven attach", &cfg, &t, PMIX_ERR_INVALID_CRED,
             "did not prove who it is", dir);
    t.attach = false;
    t.ca = cafile;
    cfg.cert = clientcert;
    one_case("a tool refuses a server whose certificate is for clients only", &cfg, &t,
             PMIX_ERR_INVALID_CRED, "did not prove who it is", dir);
    cfg.cert = bothcert;

    /* ---- refused by the server ---- */
    t.cert = foreigncert;
    t.key = foreignkey;
    one_case("a server refuses a tool whose certificate it does not trust", &cfg, &t,
             PMIX_ERR_INVALID_CRED, NULL, dir);
    t.attach = true;
    one_case("...and by an event-driven attach", &cfg, &t, PMIX_ERR_INVALID_CRED, NULL, dir);
    t.attach = false;
    t.cert = bothcert;
    t.key = keyfile;
    cfg.tools = false;
    one_case("a server that takes no tools refuses one on another host", &cfg, &t,
             PMIX_ERR_NOT_SUPPORTED, NULL, dir);
    cfg.tools = true;

    /* ---- on the wire ---- */
    raw_case("an opening naming a client is refused", RAW_CLIENT, PMIX_ERR_NOT_SUPPORTED, dir);
    raw_case("an opening offering no mechanism for one connection is refused", RAW_NO_MECH,
             PMIX_ERR_NOT_SUPPORTED, dir);
    raw_case("a credential bound to another connection is refused", RAW_WRONG_NONCE,
             PMIX_ERR_INVALID_CRED, dir);
    raw_case("a credential made as a server's is refused", RAW_AS_SERVER,
             PMIX_ERR_INVALID_CRED, dir);
    raw_case("a credential proving another user than the opening named is refused",
             RAW_OTHER_UID, PMIX_ERR_INVALID_CRED, dir);
    raw_case("a peer that gets everything right is taken", RAW_GOOD, PMIX_SUCCESS, dir);

    fprintf(stdout, "\nResults: %d passed, %d failed\n\n", npass, nfail);
    return (0 == nfail) ? 0 : 1;
}
