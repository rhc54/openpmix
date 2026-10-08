/*
 * Copyright (c) 2026      Nanook Consulting  All rights reserved.
 * $COPYRIGHT$
 *
 * Additional copyrights may follow
 *
 * $HEADER$
 *
 * Who may join a namespace on a server.
 *
 * A namespace holds either processes the host (or the server itself)
 * started - clients and tool-clients - or self-started tools, never
 * both:
 *
 *  - a client or tool-client was registered before it started, so its
 *    namespace and rank are already on the server, and it has to be the
 *    identity they were registered with. A second process connecting as
 *    the same rank - a clone - is held to the same identity;
 *  - a self-started tool builds its own namespace, and may join only a
 *    namespace another self-started tool built, as the same user;
 *  - the host may not register a client into a self-started tool's
 *    namespace, and registering a rank it already registered updates it.
 *
 * The server runs here; every connecting process is this binary re-exec'd
 * with a role, so it starts with an uninitialized library. A child
 * reports through its exit status whether it connected.
 */

#include "src/include/pmix_config.h"

#include "include/pmix.h"
#include "include/pmix_server.h"
#include "include/pmix_tool.h"
#include "src/include/pmix_globals.h"
#include "src/mca/ptl/base/base.h"
#include "src/server/pmix_server_ops.h"
#include "src/util/pmix_argv.h"
#include "src/util/pmix_printf.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

#define NSM_JOB   "nsm.job"    // a job the host registered
#define NSM_NONE  "nsm.none"   // a job nobody registered
#define NSM_SELF  "nsm.self"   // a self-started tool's job
#define NSM_FRESH "nsm.fresh"  // a tool's job the host registers during the upcall

/* child exit statuses */
#define CHILD_CONNECTED 0
#define CHILD_REFUSED   2

static int npass = 0;
static int nfail = 0;

static void report(const char *name, int passed)
{
    if (passed) {
        fprintf(stdout, "  PASS: %s\n", name);
        ++npass;
    } else {
        fprintf(stdout, "  FAIL: %s\n", name);
        ++nfail;
    }
}

/* ------------------------------------------------------------------ */
/* the connecting processes                                            */
/* ------------------------------------------------------------------ */

/* Connect as a tool. The environment decides what kind: PMIX_NAMESPACE
 * and PMIX_RANK make it a tool-client, NSM_NSPACE/NSM_RANK a self-started
 * tool with an identity of its own, and neither one that asks for one.
 * With NSM_READYFD/NSM_GOFD it stays connected until told to go. */
static int run_tool(void)
{
    pmix_proc_t me;
    pmix_info_t info[3];
    size_t ninfo = 0;
    pmix_rank_t rank;
    pmix_status_t rc;
    char *ns, *rk, *rfd, *gfd;
    char c = 'r';

    alarm(60);
    PMIX_INFO_LOAD(&info[ninfo], PMIX_SERVER_URI, getenv("NSM_URI"), PMIX_STRING);
    ++ninfo;
    ns = getenv("NSM_NSPACE");
    rk = getenv("NSM_RANK");
    if (NULL != ns && NULL != rk) {
        rank = (pmix_rank_t) strtoul(rk, NULL, 10);
        PMIX_INFO_LOAD(&info[ninfo], PMIX_TOOL_NSPACE, ns, PMIX_STRING);
        ++ninfo;
        PMIX_INFO_LOAD(&info[ninfo], PMIX_TOOL_RANK, &rank, PMIX_PROC_RANK);
        ++ninfo;
    }
    rc = PMIx_tool_init(&me, info, ninfo);
    while (0 < ninfo) {
        --ninfo;
        PMIX_INFO_DESTRUCT(&info[ninfo]);
    }
    if (PMIX_SUCCESS != rc) {
        return CHILD_REFUSED;
    }
    rfd = getenv("NSM_READYFD");
    gfd = getenv("NSM_GOFD");
    if (NULL != rfd && NULL != gfd) {
        if (1 != write(atoi(rfd), &c, 1) || 1 != read(atoi(gfd), &c, 1)) {
            PMIx_tool_finalize();
            return 1;
        }
    }
    PMIx_tool_finalize();
    return CHILD_CONNECTED;
}

static int run_client(void)
{
    pmix_proc_t me;

    alarm(60);
    if (PMIX_SUCCESS != PMIx_Init(&me, NULL, 0)) {
        return CHILD_REFUSED;
    }
    PMIx_Finalize(NULL, 0);
    return CHILD_CONNECTED;
}

/* ------------------------------------------------------------------ */
/* the host                                                            */
/* ------------------------------------------------------------------ */

/* what the tool_connected upcall answers a tool that asks for an id */
static enum {
    ASSIGN_JOB,      // the host registered job - which the tool may not join
    ASSIGN_FRESH     // a name the host registers for the tool, as PRRTE does
} assign = ASSIGN_JOB;

typedef struct {
    pmix_tool_connection_cbfunc_t cbfunc;
    void *cbdata;
} upcall_t;

static void fresh_registered(pmix_status_t status, void *cbdata)
{
    upcall_t *up = (upcall_t *) cbdata;
    pmix_proc_t proc;

    PMIX_LOAD_PROCID(&proc, NSM_FRESH, 0);
    up->cbfunc(status, &proc, up->cbdata);
    free(up);
}

static void tool_connected_fn(pmix_info_t *info, size_t ninfo,
                              pmix_tool_connection_cbfunc_t cbfunc, void *cbdata)
{
    pmix_proc_t proc;
    pmix_nspace_t fresh;
    upcall_t *up;
    pmix_status_t rc;
    bool have_ns = false;
    size_t n;

    PMIX_LOAD_PROCID(&proc, NULL, 0);
    for (n = 0; n < ninfo; n++) {
        if (PMIX_CHECK_KEY(&info[n], PMIX_NSPACE)) {
            PMIX_LOAD_NSPACE(proc.nspace, info[n].value.data.string);
            have_ns = true;
        } else if (PMIX_CHECK_KEY(&info[n], PMIX_RANK)) {
            proc.rank = info[n].value.data.rank;
        }
    }
    if (have_ns) {
        cbfunc(PMIX_SUCCESS, &proc, cbdata);
        return;
    }
    if (ASSIGN_JOB == assign) {
        PMIX_LOAD_PROCID(&proc, NSM_JOB, 0);
        cbfunc(PMIX_SUCCESS, &proc, cbdata);
        return;
    }
    /* register the tool's job before answering, as PRRTE does */
    up = (upcall_t *) malloc(sizeof(upcall_t));
    up->cbfunc = cbfunc;
    up->cbdata = cbdata;
    PMIX_LOAD_NSPACE(fresh, NSM_FRESH);
    rc = PMIx_server_register_nspace(fresh, 1, NULL, 0, fresh_registered, up);
    if (PMIX_SUCCESS != rc) {
        free(up);
        cbfunc(rc, NULL, cbdata);
    }
}

static pmix_server_module_t mymodule = {
    .tool_connected = tool_connected_fn
};

static char *server_uri = NULL;
static char *self_argv0 = NULL;

/* the environment a child starts with: ours, less anything that would
 * tell it who it is, plus what the case adds */
static char **child_env(char **extra)
{
    char **env = NULL;
    size_t n;

    for (n = 0; NULL != environ[n]; n++) {
        if (0 == strncmp(environ[n], "PMIX_NAMESPACE=", 15) ||
            0 == strncmp(environ[n], "PMIX_RANK=", 10) ||
            0 == strncmp(environ[n], "PMIX_SERVER_URI", 15) ||
            0 == strncmp(environ[n], "NSM_", 4)) {
            continue;
        }
        PMIx_Argv_append_nosize(&env, environ[n]);
    }
    for (n = 0; NULL != extra && NULL != extra[n]; n++) {
        PMIx_Argv_append_nosize(&env, extra[n]);
    }
    return env;
}

/* start this binary as role with env, without waiting */
static pid_t launch(const char *role, char **env)
{
    char *argv[3];
    pid_t child;

    argv[0] = self_argv0;
    argv[1] = (char *) role;
    argv[2] = NULL;
    child = fork();
    if (0 == child) {
        execve(self_argv0, argv, env);
        _exit(127);
    }
    return child;
}

static int reap(pid_t child)
{
    int status;

    if (0 > child || child != waitpid(child, &status, 0) || !WIFEXITED(status)) {
        return -1;
    }
    return WEXITSTATUS(status);
}

/* run a tool to completion and return its exit status */
static int tool(const char *nspace, const char *rank, bool tool_client)
{
    char **extra = NULL, **env;
    char *tmp;
    int rc;

    pmix_asprintf(&tmp, "NSM_URI=%s", server_uri);
    PMIx_Argv_append_nosize(&extra, tmp);
    free(tmp);
    if (NULL != nspace) {
        pmix_asprintf(&tmp, "%s=%s", tool_client ? "PMIX_NAMESPACE" : "NSM_NSPACE", nspace);
        PMIx_Argv_append_nosize(&extra, tmp);
        free(tmp);
        pmix_asprintf(&tmp, "%s=%s", tool_client ? "PMIX_RANK" : "NSM_RANK", rank);
        PMIx_Argv_append_nosize(&extra, tmp);
        free(tmp);
    }
    env = child_env(extra);
    rc = reap(launch("tool", env));
    PMIx_Argv_free(extra);
    PMIx_Argv_free(env);
    return rc;
}

static pmix_namespace_t *find_nspace(const char *nspace)
{
    pmix_namespace_t *ns;

    PMIX_LIST_FOREACH (ns, &pmix_globals.nspaces, pmix_namespace_t) {
        if (NULL != ns->nspace && 0 == strcmp(ns->nspace, nspace)) {
            return ns;
        }
    }
    return NULL;
}

static size_t count_rank(pmix_namespace_t *ns, pmix_rank_t rank, pmix_rank_info_t **out)
{
    pmix_rank_info_t *info;
    size_t count = 0;

    PMIX_LIST_FOREACH (info, &ns->ranks, pmix_rank_info_t) {
        if (info->pname.rank == rank) {
            ++count;
            *out = info;
        }
    }
    return count;
}

static void opcb(pmix_status_t status, void *cbdata)
{
    pmix_status_t *st = (pmix_status_t *) cbdata;
    *st = status;
}

/* register a client, waiting for the outcome */
static pmix_status_t register_client(const char *nspace, pmix_rank_t rank, uid_t uid, gid_t gid)
{
    pmix_proc_t proc;
    volatile pmix_status_t st = PMIX_ERR_NOT_AVAILABLE + 1000;
    pmix_status_t rc;
    int n;

    PMIX_LOAD_PROCID(&proc, nspace, rank);
    rc = PMIx_server_register_client(&proc, uid, gid, NULL, opcb, (void *) &st);
    if (PMIX_SUCCESS != rc) {
        return rc;
    }
    for (n = 0; n < 1000 && PMIX_ERR_NOT_AVAILABLE + 1000 == st; n++) {
        usleep(10000);
    }
    return st;
}

static void self_started_cases(void)
{
    int ready[2], go[2];
    char **extra = NULL, **env;
    char *tmp, c = 'g';
    pid_t holder;
    pmix_namespace_t *ns;
    pmix_proc_t proc;

    /* a self-started tool builds nsm.self and stays connected */
    if (0 != pipe(ready) || 0 != pipe(go)) {
        report("self-started tool held connected", 0);
        return;
    }
    fcntl(ready[0], F_SETFD, FD_CLOEXEC);
    fcntl(go[1], F_SETFD, FD_CLOEXEC);
    pmix_asprintf(&tmp, "NSM_URI=%s", server_uri);
    PMIx_Argv_append_nosize(&extra, tmp);
    free(tmp);
    PMIx_Argv_append_nosize(&extra, "NSM_NSPACE=" NSM_SELF);
    PMIx_Argv_append_nosize(&extra, "NSM_RANK=0");
    pmix_asprintf(&tmp, "NSM_READYFD=%d", ready[1]);
    PMIx_Argv_append_nosize(&extra, tmp);
    free(tmp);
    pmix_asprintf(&tmp, "NSM_GOFD=%d", go[0]);
    PMIx_Argv_append_nosize(&extra, tmp);
    free(tmp);
    env = child_env(extra);
    holder = launch("tool", env);
    PMIx_Argv_free(extra);
    PMIx_Argv_free(env);
    close(ready[1]);
    close(go[0]);
    if (1 != read(ready[0], &c, 1)) {
        report("self-started tool connects with its own namespace", 0);
        close(go[1]);
        close(ready[0]);
        reap(holder);
        return;
    }
    report("self-started tool connects with its own namespace", 1);
    ns = find_nspace(NSM_SELF);
    report("its namespace is marked as a self-started tool's",
           NULL != ns && ns->self_started);

    report("the host cannot register a client into it",
           PMIX_ERR_NOT_SUPPORTED == register_client(NSM_SELF, 1, getuid(), getgid()));

    /* a client naming the tool's rank - the env a client of the host's
     * job gets, retargeted at the tool's namespace */
    extra = NULL;
    PMIX_LOAD_PROCID(&proc, NSM_JOB, 0);
    env = child_env(NULL);
    if (PMIX_SUCCESS == PMIx_server_setup_fork(&proc, &env)) {
        PMIx_Setenv("PMIX_NAMESPACE", NSM_SELF, true, &env);
        PMIx_Setenv("PMIX_RANK", "0", true, &env);
        report("a client cannot connect into it",
               CHILD_REFUSED == reap(launch("client", env)));
    } else {
        report("a client cannot connect into it", 0);
    }
    PMIx_Argv_free(env);

    report("a second self-started tool of the same user joins it",
           CHILD_CONNECTED == tool(NSM_SELF, "1", false));
    report("a tool-client cannot connect into it",
           CHILD_REFUSED == tool(NSM_SELF, "0", true));

    /* let the first tool go */
    if (1 != write(go[1], &c, 1)) {
        /* it is gone already */
    }
    close(go[1]);
    close(ready[0]);
    report("the first self-started tool finalized cleanly", CHILD_CONNECTED == reap(holder));
}

int main(int argc, char **argv)
{
    pmix_status_t rc;
    pmix_info_t sinfo;
    pmix_namespace_t *ns;
    pmix_rank_info_t *info = NULL;
    pmix_nspace_t job;
    volatile pmix_status_t st;
    bool flag = true;
    int n;

    if (1 < argc && 0 == strcmp(argv[1], "tool")) {
        return run_tool();
    }
    if (1 < argc && 0 == strcmp(argv[1], "client")) {
        return run_client();
    }
    self_argv0 = argv[0];

    fprintf(stdout, "\n=== namespace membership unit test ===\n\n");

    PMIX_INFO_LOAD(&sinfo, PMIX_SERVER_TOOL_SUPPORT, &flag, PMIX_BOOL);
    rc = PMIx_server_init(&mymodule, &sinfo, 1);
    PMIX_INFO_DESTRUCT(&sinfo);
    if (PMIX_SUCCESS != rc) {
        fprintf(stderr, "PMIx_server_init failed: %s\n", PMIx_Error_string(rc));
        return 1;
    }
    server_uri = pmix_ptl_base.listener.uri;
    if (NULL == server_uri) {
        fprintf(stderr, "the server has no URI\n");
        PMIx_server_finalize();
        return 1;
    }

    /* the host's job: rank 0 is us, rank 2 another user, rank 1 nobody */
    st = PMIX_ERR_NOT_AVAILABLE + 1000;
    PMIX_LOAD_NSPACE(job, NSM_JOB);
    rc = PMIx_server_register_nspace(job, 3, NULL, 0, opcb, (void *) &st);
    for (n = 0; PMIX_SUCCESS == rc && n < 1000 && PMIX_ERR_NOT_AVAILABLE + 1000 == st; n++) {
        usleep(10000);
    }
    report("the host registers its job",
           PMIX_SUCCESS == rc && PMIX_SUCCESS == st &&
           PMIX_SUCCESS == register_client(NSM_JOB, 0, getuid(), getgid()) &&
           PMIX_SUCCESS == register_client(NSM_JOB, 2, getuid() + 1, getgid()));

    /* tool-clients */
    report("a tool-client of an unregistered namespace is refused",
           CHILD_REFUSED == tool(NSM_NONE, "0", true));
    report("a tool-client of an unregistered rank is refused",
           CHILD_REFUSED == tool(NSM_JOB, "1", true));
    report("a tool-client that is not its rank's user is refused",
           CHILD_REFUSED == tool(NSM_JOB, "2", true));
    report("a tool-client of its own registered rank connects",
           CHILD_CONNECTED == tool(NSM_JOB, "0", true));

    /* self-started tools */
    report("a self-started tool cannot join the host's job",
           CHILD_REFUSED == tool(NSM_JOB, "5", false));
    self_started_cases();

    /* a tool the host hands an identity during the upcall */
    assign = ASSIGN_JOB;
    report("a tool cannot be handed the host's job as its identity",
           CHILD_REFUSED == tool(NULL, NULL, false));
    assign = ASSIGN_FRESH;
    report("a tool whose job the host registers during the upcall connects",
           CHILD_CONNECTED == tool(NULL, NULL, false));
    ns = find_nspace(NSM_FRESH);
    report("that namespace is marked as a self-started tool's",
           NULL != ns && ns->self_started);

    /* registering a rank again updates it */
    report("registering a rank again succeeds",
           PMIX_SUCCESS == register_client(NSM_JOB, 0, getuid() + 7, getgid()));
    ns = find_nspace(NSM_JOB);
    report("and updates the one entry for it",
           NULL != ns && 1 == count_rank(ns, 0, &info) && NULL != info &&
           getuid() + 7 == info->uid);

    PMIx_server_finalize();

    fprintf(stdout, "\n%d passed, %d failed\n", npass, nfail);
    return (0 == nfail) ? 0 : 1;
}
