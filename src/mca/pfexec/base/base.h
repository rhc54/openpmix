/*
 * Copyright (c) 2004-2006 The Trustees of Indiana University and Indiana
 *                         University Research and Technology
 *                         Corporation.  All rights reserved.
 * Copyright (c) 2004-2011 The University of Tennessee and The University
 *                         of Tennessee Research Foundation.  All rights
 *                         reserved.
 * Copyright (c) 2004-2005 High Performance Computing Center Stuttgart,
 *                         University of Stuttgart.  All rights reserved.
 * Copyright (c) 2004-2005 The Regents of the University of California.
 *                         All rights reserved.
 * Copyright (c) 2011 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2013      Los Alamos National Security, LLC.  All rights reserved.
 * Copyright (c) 2017-2020 Intel, Inc.  All rights reserved.
 * Copyright (c) 2021-2024 Nanook Consulting  All rights reserved.
 * $COPYRIGHT$
 *
 * Additional copyrights may follow
 *
 * $HEADER$
 */
/** @file:
 */

#ifndef MCA_PFEXEC_BASE_H
#define MCA_PFEXEC_BASE_H

/*
 * includes
 */
#include "pmix_config.h"

#include "src/class/pmix_list.h"
#include "src/common/pmix_iof.h"
#include "src/mca/mca.h"
#include "src/mca/pfexec/pfexec.h"
#include "src/mca/pfexec/pfexec_types.h"

BEGIN_C_DECLS

/*
 * MCA framework
 */
PMIX_EXPORT extern pmix_mca_base_framework_t pmix_pfexec_base_framework;
/*
 * Select an available component.
 */
PMIX_EXPORT pmix_status_t pmix_pfexec_base_select(void);

typedef struct {
    pmix_event_t *handler;
    bool active;
    pmix_list_t children;
    int timeout_before_sigkill;
    size_t nextid;
    bool selected;
} pmix_pfexec_globals_t;

PMIX_EXPORT extern pmix_pfexec_globals_t pmix_pfexec_globals;

typedef struct {
    pmix_object_t super;
    pmix_event_t ev;
    pmix_proc_t *proc;
    int signal;
    pmix_pfexec_base_signal_local_fn_t sigfn;
    pmix_lock_t *lock;
} pmix_pfexec_signal_caddy_t;
PMIX_EXPORT PMIX_CLASS_DECLARATION(pmix_pfexec_signal_caddy_t);

PMIX_EXPORT void pmix_pfexec_base_spawn_proc(int sd, short args, void *cbdata);

PMIX_EXPORT void pmix_pfexec_base_kill_proc(int sd, short args, void *cbdata);

PMIX_EXPORT void pmix_pfexec_base_signal_proc(int sd, short args, void *cbdata);

PMIX_EXPORT void pmix_pfexec_check_complete(int sd, short args, void *cbdata);

#define PMIX_PFEXEC_SPAWN(fcd)                    \
    do {                                                                 \
        pmix_event_assign(&(fcd->ev), pmix_globals.evbase, -1, EV_WRITE, \
                          pmix_pfexec_base_spawn_proc, fcd);             \
        PMIX_POST_OBJECT((fcd));                                         \
        pmix_event_active(&((fcd)->ev), EV_WRITE, 1);                    \
    } while (0)

#define PMIX_PFEXEC_KILL(scd, r, fn, lk)                                   \
    do {                                                                   \
        (scd) = PMIX_NEW(pmix_pfexec_signal_caddy_t);                      \
        (scd)->proc = (r);                                                 \
        (scd)->sigfn = (fn);                                               \
        (scd)->lock = (lk);                                                \
        pmix_event_assign(&((scd)->ev), pmix_globals.evbase, -1, EV_WRITE, \
                          pmix_pfexec_base_kill_proc, (scd));              \
        PMIX_POST_OBJECT((scd));                                           \
        pmix_event_active(&((scd)->ev), EV_WRITE, 1);                      \
    } while (0)

#define PMIX_PFEXEC_SIGNAL(scd, r, nm, fn, lk)                             \
    do {                                                                   \
        (scd) = PMIX_NEW(pmix_pfexec_signal_caddy_t);                      \
        (scd)->proc = (r);                                                 \
        (scd)->signal = (nm);                                              \
        (scd)->sigfn = (fn);                                               \
        (scd)->lock = (lk);                                                \
        pmix_event_assign(&((scd)->ev), pmix_globals.evbase, -1, EV_WRITE, \
                          pmix_pfexec_base_signal_proc, (scd));            \
        PMIX_POST_OBJECT((scd));                                           \
        pmix_event_active(&((scd)->ev), EV_WRITE, 1);                      \
    } while (0)

typedef struct {
    pmix_object_t super;
    pmix_event_t ev;
    pmix_pfexec_child_t *child;
} pmix_pfexec_cmpl_caddy_t;
PMIX_EXPORT PMIX_CLASS_DECLARATION(pmix_pfexec_cmpl_caddy_t);

#define PMIX_PFEXEC_CHK_COMPLETE(c)                                        \
    do {                                                                   \
        pmix_pfexec_cmpl_caddy_t *pc = PMIX_NEW(pmix_pfexec_cmpl_caddy_t); \
        pc->child = (c);                                                   \
        pmix_event_assign(&((pc)->ev), pmix_globals.evbase, -1, EV_WRITE,  \
                          pmix_pfexec_check_complete, (pc));               \
        PMIX_POST_OBJECT((pc));                                            \
        pmix_event_active(&((pc)->ev), EV_WRITE, 1);                       \
    } while (0)

/*
 * Struct written up the pipe from the child to the parent.
 */
typedef struct {
    /* True if the child has died; false if this is just a warning to
       be printed. */
    bool fatal;
    /* Relevant only if fatal==true */
    int exit_status;

    /* Length of the strings that are written up the pipe after this
       struct */
    int file_str_len;
    int topic_str_len;
    int msg_str_len;
} pmix_pfexec_pipe_err_msg_t;

PMIX_EXPORT pmix_status_t pmix_pfexec_base_setup_child(pmix_pfexec_child_t *child);

/*
 * Max length of strings from the pmix_pfexec_pipe_err_msg_t
 */
#define PMIX_PFEXEC_MAX_FILE_LEN  511
#define PMIX_PFEXEC_MAX_TOPIC_LEN PMIX_PFEXEC_MAX_FILE_LEN

END_C_DECLS
#endif
