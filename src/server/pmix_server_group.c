/* -*- Mode: C; c-basic-offset:4 ; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2014-2020 Intel, Inc.  All rights reserved.
 * Copyright (c) 2014-2019 Research Organization for Information Science
 *                         and Technology (RIST).  All rights reserved.
 * Copyright (c) 2014-2015 Artem Y. Polyakov <artpol84@gmail.com>.
 *                         All rights reserved.
 * Copyright (c) 2016-2019 Mellanox Technologies, Inc.
 *                         All rights reserved.
 * Copyright (c) 2016-2020 IBM Corporation.  All rights reserved.
 * Copyright (c) 2021-2024 Nanook Consulting  All rights reserved.
 * Copyright (c) 2022-2023 Triad National Security, LLC. All rights reserved.
 * $COPYRIGHT$
 *
 * Additional copyrights may follow
 *
 * $HEADER$
 */

#include "src/include/pmix_config.h"

#include "src/include/pmix_socket_errno.h"
#include "src/include/pmix_stdint.h"

#include "include/pmix_server.h"
#include "src/include/pmix_globals.h"

#ifdef HAVE_STRING_H
#    include <string.h>
#endif
#ifdef HAVE_SYS_STAT_H
#    include <sys/stat.h>
#endif
#include <fcntl.h>
#ifdef HAVE_UNISTD_H
#    include <unistd.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#    include <sys/socket.h>
#endif
#ifdef HAVE_SYS_UN_H
#    include <sys/un.h>
#endif
#ifdef HAVE_SYS_UIO_H
#    include <sys/uio.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#    include <sys/types.h>
#endif
#ifdef HAVE_TIME_H
#    include <time.h>
#endif
#include <event.h>

#ifndef MAX
#    define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#include "src/class/pmix_hotel.h"
#include "src/class/pmix_list.h"
#include "src/common/pmix_attributes.h"
#include "src/common/pmix_iof.h"
#include "src/hwloc/pmix_hwloc.h"
#include "src/mca/bfrops/base/base.h"
#include "src/mca/gds/base/base.h"
#include "src/mca/plog/plog.h"
#include "src/mca/pnet/pnet.h"
#include "src/mca/prm/prm.h"
#include "src/mca/psensor/psensor.h"
#include "src/mca/ptl/base/base.h"
#include "src/util/pmix_argv.h"
#include "src/util/pmix_error.h"
#include "src/util/pmix_name_fns.h"
#include "src/util/pmix_output.h"
#include "src/util/pmix_environ.h"

#include "src/client/pmix_client_ops.h"
#include "pmix_server_ops.h"


static void _grpcbfunc(int sd, short args, void *cbdata)
{
    pmix_shift_caddy_t *scd = (pmix_shift_caddy_t *) cbdata;
    pmix_server_trkr_t *trk = scd->tracker;
    pmix_server_caddy_t *cd;
    pmix_buffer_t *reply, xfer;
    pmix_status_t ret;
    size_t n, ctxid = SIZE_MAX, nmembers = 0;
    pmix_proc_t *members = NULL, proc;
    pmix_byte_object_t *jbo = NULL;
    pmix_nspace_caddy_t *nptr;
    pmix_list_t nslist;
    bool found;
    bool ctxid_given = false;
    pmix_list_t grpinfo, endpts;
    pmix_info_caddy_t *g, *ept;
    pmix_info_t info;
    pmix_gds_base_module_t *gds;
    int32_t cnt;
    pmix_kval_t kv;
    PMIX_HIDE_UNUSED_PARAMS(sd, args);

    PMIX_ACQUIRE_OBJECT(scd);

    if (NULL == trk) {
        /* give them a release if they want it - this should
         * never happen, but protect against the possibility */
        if (NULL != scd->cbfunc.relfn) {
            scd->cbfunc.relfn(scd->cbdata);
        }
        PMIX_RELEASE(scd);
        return;
    }

    pmix_output_verbose(2, pmix_server_globals.group_output,
                        "server:grpcbfunc processing WITH %d CALLBACKS",
                        (int) pmix_list_get_size(&trk->local_cbs));


    // if this is a destruct operation, there is nothing more to do
    if (PMIX_GROUP_DESTRUCT == trk->grpop) {
        goto release;
    }

    /* see if this group was assigned a context ID or collected data */
    PMIX_CONSTRUCT(&grpinfo, pmix_list_t);
    PMIX_CONSTRUCT(&endpts, pmix_list_t);
    for (n = 0; n < scd->ninfo; n++) {
        if (PMIX_CHECK_KEY(&scd->info[n], PMIX_GROUP_CONTEXT_ID)) {
            PMIX_VALUE_GET_NUMBER(ret, &scd->info[n].value, ctxid, size_t);
            if (PMIX_SUCCESS != ret) {
                PMIX_ERROR_LOG(ret);
            } else {
                ctxid_given = true;
            }

        } else if (PMIX_CHECK_KEY(&scd->info[n], PMIX_GROUP_ENDPT_DATA)) {
            ept = PMIX_NEW(pmix_info_caddy_t);
            ept->info = &scd->info[n];
            ept->ninfo = 1;
            pmix_list_append(&endpts, &ept->super);

        } else if (PMIX_CHECK_KEY(&scd->info[n], PMIX_GROUP_MEMBERSHIP)) {
            members = (pmix_proc_t*)scd->info[n].value.data.darray->array;
            nmembers = scd->info[n].value.data.darray->size;

        } else if (PMIX_CHECK_KEY(&scd->info[n], PMIX_GROUP_INFO)) {
            g = PMIX_NEW(pmix_info_caddy_t);
            g->info = &scd->info[n];
            pmix_list_append(&grpinfo, &g->super);

        } else if (PMIX_CHECK_KEY(&scd->info[n], PMIX_GROUP_JOB_INFO)) {
            jbo = &scd->info[n].value.data.bo;

        }
    }

    /* Collect the nptr list of all participants */
    PMIX_CONSTRUCT(&nslist, pmix_list_t);
    PMIX_LIST_FOREACH (cd, &trk->local_cbs, pmix_server_caddy_t) {
        // see if we already have this nspace
        found = false;
        PMIX_LIST_FOREACH (nptr, &nslist, pmix_nspace_caddy_t) {
            // if we already have this nspace, ignore this entry
            if (PMIX_CHECK_NSPACE(nptr->ns->nspace, cd->peer->nptr->nspace)) {
                found = true;
                break;
            }
        }
        if (!found) {
            // add it
            nptr = PMIX_NEW(pmix_nspace_caddy_t);
            PMIX_RETAIN(cd->peer->nptr);
            nptr->ns = cd->peer->nptr;
            pmix_list_append(&nslist, &nptr->super);
        }
    }

    /* if endpt data was returned, then we need to
     * store it before releasing the group members */
    if (0 < pmix_list_get_size(&endpts)) {

        /* Each list member points to a pmix_info_t that contains
         * a single byte object that needs to be unpacked */
        PMIX_LIST_FOREACH(ept, &endpts, pmix_info_caddy_t) {
            PMIX_CONSTRUCT(&xfer, pmix_buffer_t);
            PMIX_LOAD_BUFFER(pmix_globals.mypeer, &xfer,
                             ept->info->value.data.bo.bytes,
                             ept->info->value.data.bo.size);
            // unpack the procID for this data
            cnt = 1;
            PMIX_BFROPS_UNPACK(ret, pmix_globals.mypeer, &xfer, &proc, &cnt, PMIX_PROC);
            if (PMIX_SUCCESS != ret) {
                PMIX_ERROR_LOG(ret);
                PMIX_DESTRUCT(&xfer);
                continue;
            }
            // unpack the provided info until we hit the end
            // of the buffer
            cnt = 1;
            PMIX_BFROPS_UNPACK(ret, pmix_globals.mypeer, &xfer, &info, &cnt, PMIX_INFO);
            if (PMIX_SUCCESS != ret) {
                PMIX_ERROR_LOG(ret);
                PMIX_DESTRUCT(&xfer);
                continue;
            }
            while (PMIX_SUCCESS == ret) {
                kv.key = info.key;
                kv.value = &info.value;
                // store it for every nspace
                PMIX_LIST_FOREACH (nptr, &nslist, pmix_nspace_caddy_t) {
                    gds = nptr->ns->compat.gds;
                    if (NULL == gds || NULL == gds->store) {
                        // should never happen
                        continue;
                    }
                    ret = gds->store(&proc, PMIX_REMOTE, &kv);
                    if (PMIX_SUCCESS != ret) {
                        PMIX_ERROR_LOG(ret);
                        continue;
                    }
                }
                cnt = 1;
                PMIX_BFROPS_UNPACK(ret, pmix_globals.mypeer, &xfer, &info, &cnt, PMIX_INFO);
            }
            PMIX_DESTRUCT(&xfer);
        }
    }

    // if group info was returned, then we need to store it
    // as well before releasing the group members


    // if job info was returned, then we need to store it
    // as well before releasing the group members


    // cleanup the namespace list
    PMIX_LIST_DESTRUCT(&nslist);


release:
    /* loop across all procs in the tracker, sending them the reply */
    PMIX_LIST_FOREACH (cd, &trk->local_cbs, pmix_server_caddy_t) {
        reply = PMIX_NEW(pmix_buffer_t);
        if (NULL == reply) {
            break;
        }
        /* setup the reply, starting with the returned status */
        PMIX_BFROPS_PACK(ret, cd->peer, reply, &scd->status, 1, PMIX_STATUS);
        if (PMIX_SUCCESS != ret) {
            PMIX_ERROR_LOG(ret);
            PMIX_RELEASE(reply);
            break;
        }
        if (PMIX_SUCCESS == scd->status && PMIX_GROUP_CONSTRUCT == trk->grpop) {
            /* add the final membership */
            PMIX_BFROPS_PACK(ret, cd->peer, reply, &nmembers, 1, PMIX_SIZE);
            if (PMIX_SUCCESS != ret) {
                PMIX_ERROR_LOG(ret);
                PMIX_RELEASE(reply);
                break;
            }
            if (0 < nmembers) {
                PMIX_BFROPS_PACK(ret, cd->peer, reply, members, nmembers, PMIX_PROC);
                if (PMIX_SUCCESS != ret) {
                    PMIX_ERROR_LOG(ret);
                    PMIX_RELEASE(reply);
                    break;
                }
            }
            /* if a ctxid was provided, pass it along */
            PMIX_BFROPS_PACK(ret, cd->peer, reply, &ctxid_given, 1, PMIX_BOOL);
            if (PMIX_SUCCESS != ret) {
                PMIX_ERROR_LOG(ret);
                PMIX_RELEASE(reply);
                break;
            }
            if (ctxid_given) {
                PMIX_BFROPS_PACK(ret, cd->peer, reply, &ctxid, 1, PMIX_SIZE);
                if (PMIX_SUCCESS != ret) {
                    PMIX_ERROR_LOG(ret);
                    PMIX_RELEASE(reply);
                    break;
                }
            }
            if (NULL != jbo) {
                // we were given job-level info to pass along
                PMIX_BFROPS_PACK(ret, cd->peer, reply, &jbo, 1, PMIX_BYTE_OBJECT);
            }
        }

        pmix_output_verbose(2, pmix_server_globals.group_output,
                            "server:grp_cbfunc reply being sent to %s:%u",
                            cd->peer->info->pname.nspace, cd->peer->info->pname.rank);
        PMIX_SERVER_QUEUE_REPLY(ret, cd->peer, cd->hdr.tag, reply);
        if (PMIX_SUCCESS != ret) {
            PMIX_RELEASE(reply);
        }
    }

    /* remove the tracker from the list */
    pmix_list_remove_item(&pmix_server_globals.collectives, &trk->super);
    PMIX_RELEASE(trk);

    /* we are done */
    if (NULL != scd->cbfunc.relfn) {
        scd->cbfunc.relfn(scd->cbdata);
    }
    PMIX_RELEASE(scd);
}

static void grpcbfunc(pmix_status_t status,
                      pmix_info_t *info, size_t ninfo, void *cbdata,
                      pmix_release_cbfunc_t relfn, void *relcbd)
{
    pmix_server_trkr_t *tracker = (pmix_server_trkr_t *) cbdata;
    pmix_shift_caddy_t *scd;

    pmix_output_verbose(2, pmix_server_globals.group_output,
                        "server:grpcbfunc called with %d info", (int) ninfo);

    if (NULL == tracker) {
        /* nothing to do - but be sure to give them
         * a release if they want it */
        if (NULL != relfn) {
            relfn(relcbd);
        }
        return;
    }
    /* need to thread-shift this callback as it accesses global data */
    scd = PMIX_NEW(pmix_shift_caddy_t);
    if (NULL == scd) {
        /* nothing we can do */
        if (NULL != relfn) {
            relfn(cbdata);
        }
        return;
    }
    scd->status = status;
    scd->info = info;
    scd->ninfo = ninfo;
    scd->tracker = tracker;
    scd->cbfunc.relfn = relfn;
    scd->cbdata = relcbd;
    PMIX_THREADSHIFT(scd, _grpcbfunc);
}

static void grp_timeout(int sd, short args, void *cbdata)
{
    pmix_server_trkr_t *trk = (pmix_server_trkr_t *) cbdata;
    pmix_server_caddy_t *cd;
    pmix_buffer_t *reply;
    pmix_status_t ret, rc = PMIX_ERR_TIMEOUT;
    PMIX_HIDE_UNUSED_PARAMS(sd, args);

    pmix_output_verbose(2, pmix_server_globals.group_output,
                        "ALERT: grp construct timeout fired");

    /* loop across all procs in the tracker, alerting
     * them to the failure */
    PMIX_LIST_FOREACH (cd, &trk->local_cbs, pmix_server_caddy_t) {
        reply = PMIX_NEW(pmix_buffer_t);
        if (NULL == reply) {
            break;
        }
        /* setup the reply, starting with the returned status */
        PMIX_BFROPS_PACK(ret, cd->peer, reply, &rc, 1, PMIX_STATUS);
        if (PMIX_SUCCESS != ret) {
            PMIX_ERROR_LOG(ret);
            PMIX_RELEASE(reply);
            break;
        }
        pmix_output_verbose(2, pmix_server_globals.group_output,
                            "server:grp_cbfunc TIMEOUT being sent to %s:%u",
                            cd->peer->info->pname.nspace, cd->peer->info->pname.rank);
        PMIX_SERVER_QUEUE_REPLY(ret, cd->peer, cd->hdr.tag, reply);
        if (PMIX_SUCCESS != ret) {
            PMIX_RELEASE(reply);
        }
    }

    trk->event_active = false;
    /* record this group as failed */
    PMIx_Argv_append_nosize(&pmix_server_globals.failedgrps, trk->id);
    /* remove the tracker from the list */
    pmix_list_remove_item(&pmix_server_globals.collectives, &trk->super);
    PMIX_RELEASE(trk);
}

static pmix_status_t aggregate_info(pmix_server_trkr_t *trk,
                                    pmix_info_t *info, size_t ninfo)
{
    pmix_list_t ilist, nmlist;
    size_t n, m, j, k, niptr;
    pmix_info_t *iptr;
    bool found, nmfound;
    pmix_info_caddy_t *icd;
    pmix_proclist_t *nm;
    pmix_proc_t *nmarray, *trkarray;
    size_t nmsize, trksize, bt, bt2;
    pmix_status_t rc;

    if (NULL == trk->info) {
        trk->info = info;
        trk->ninfo = ninfo;
        return PMIX_EXISTS;
    }

    // only keep unique entries
    PMIX_CONSTRUCT(&ilist, pmix_list_t);
    for (m=0; m < ninfo; m++) {
        found = false;
        for (n=0; n < trk->ninfo; n++) {
            if (PMIX_CHECK_KEY(&trk->info[n], info[m].key)) {

                // check a few critical keys
                if (PMIX_CHECK_KEY(&info[m], PMIX_GROUP_ADD_MEMBERS)) {
                    // aggregate the members
                    nmarray = (pmix_proc_t*)info[m].value.data.darray->array;
                    nmsize = info[m].value.data.darray->size;
                    trkarray = (pmix_proc_t*)trk->info[n].value.data.darray->array;
                    trksize = trk->info[n].value.data.darray->size;
                    PMIX_CONSTRUCT(&nmlist, pmix_list_t);
                    // sadly, an exhaustive search
                    for (j=0; j < nmsize; j++) {
                        nmfound = false;
                        for (k=0; k < trksize; k++) {
                            if (PMIX_CHECK_PROCID(&nmarray[j], &trkarray[k])) {
                                // if the new one is rank=WILDCARD, then ensure
                                // we keep it as wildcard
                                if (PMIX_RANK_WILDCARD == nmarray[j].rank) {
                                    trkarray[k].rank = PMIX_RANK_WILDCARD;
                                }
                                nmfound = true;
                                break;
                            }
                        }
                        if (!nmfound) {
                            nm = PMIX_NEW(pmix_proclist_t);
                            memcpy(&nm->proc, &nmarray[j], sizeof(pmix_proc_t));
                            pmix_list_append(&nmlist, &nm->super);
                        }
                    }
                    // create the replacement array, if needed
                    if (0 < pmix_list_get_size(&nmlist)) {
                        nmsize = trksize + pmix_list_get_size(&nmlist);
                        PMIX_PROC_CREATE(nmarray, nmsize);
                        memcpy(nmarray, trkarray, trksize * sizeof(pmix_proc_t));
                        j = trksize;
                        PMIX_LIST_FOREACH(nm, &nmlist, pmix_proclist_t) {
                            memcpy(&nmarray[j], &nm->proc, sizeof(pmix_proc_t));
                            ++j;
                        }
                        PMIX_PROC_FREE(trkarray, trksize);
                        trk->info[n].value.data.darray->array = nmarray;
                        trk->info[n].value.data.darray->size = nmsize;
                    }
                    PMIX_LIST_DESTRUCT(&nmlist);

                } else if (PMIX_CHECK_KEY(&info[m], PMIX_GROUP_BOOTSTRAP)) {
                    // the numbers must match
                    PMIX_VALUE_GET_NUMBER(rc, &info[m].value, bt, size_t);
                    if (PMIX_SUCCESS != rc) {
                        PMIX_LIST_DESTRUCT(&ilist);
                        return rc;
                    }
                    PMIX_VALUE_GET_NUMBER(rc, &trk->info[n].value, bt2, size_t);
                    if (PMIX_SUCCESS != rc) {
                        PMIX_LIST_DESTRUCT(&ilist);
                        return rc;
                    }
                    if (bt != bt2) {
                        PMIX_LIST_DESTRUCT(&ilist);
                        return PMIX_ERR_BAD_PARAM;
                    }
                }
                found = true;
                break;
            }
        }
        if (!found) {
            // add this one in
            icd = PMIX_NEW(pmix_info_caddy_t);
            icd->info = &info[m];
            icd->ninfo = 1;
            pmix_list_append(&ilist, &icd->super);
        }
    }
    if (0 < pmix_list_get_size(&ilist)) {
        niptr = trk->ninfo + pmix_list_get_size(&ilist);
        PMIX_INFO_CREATE(iptr, niptr);
        for (n=0; n < trk->ninfo; n++) {
            PMIX_INFO_XFER(&iptr[n], &trk->info[n]);
        }
        n = trk->ninfo;
        PMIX_LIST_FOREACH(icd, &ilist, pmix_info_caddy_t) {
            PMIX_INFO_XFER(&iptr[n], icd->info);
            ++n;
        }
        PMIX_INFO_FREE(trk->info, trk->ninfo);
        trk->info = iptr;
        trk->ninfo = niptr;
        /* cleanup */
    }
    PMIX_LIST_DESTRUCT(&ilist);
    return PMIX_SUCCESS;
}

/* we are being called from the PMIx server's switchyard function,
 * which means we are in an event and can access global data */
pmix_status_t pmix_server_grpconstruct(pmix_server_caddy_t *cd, pmix_buffer_t *buf)
{
    pmix_peer_t *peer = (pmix_peer_t *) cd->peer;
    pmix_peer_t *pr;
    int32_t cnt, m;
    pmix_status_t rc;
    char *grpid;
    pmix_proc_t *procs;
    pmix_info_t *info = NULL, *iptr;
    size_t n, ninfo, ninf, nprocs;
    pmix_server_trkr_t *trk;
    bool need_cxtid = false;
    bool match, force_local = false;
    bool locally_complete = false;
    bool bootstrap = false;
    struct timeval tv = {0, 0};
    pmix_list_t xfer;
    pmix_info_caddy_t *ncd;

    pmix_output_verbose(2, pmix_server_globals.group_output,
                        "recvd grpconstruct cmd from %s",
                        PMIX_PEER_PRINT(cd->peer));

    /* unpack the group ID */
    cnt = 1;
    PMIX_BFROPS_UNPACK(rc, peer, buf, &grpid, &cnt, PMIX_STRING);
    if (PMIX_SUCCESS != rc) {
        PMIX_ERROR_LOG(rc);
        goto error;
    }

    /* is this a failed group? */
    if (NULL != pmix_server_globals.failedgrps) {
        for (m=0; NULL != pmix_server_globals.failedgrps[m]; m++) {
            if (0 == strcmp(grpid, pmix_server_globals.failedgrps[m])) {
                /* yes - reject it */
                free(grpid);
                return PMIX_ERR_TIMEOUT;
            }
        }
    }

    /* unpack the number of procs */
    cnt = 1;
    PMIX_BFROPS_UNPACK(rc, peer, buf, &nprocs, &cnt, PMIX_SIZE);
    if (PMIX_SUCCESS != rc) {
        PMIX_ERROR_LOG(rc);
        goto error;
    }
    if (0 < nprocs) {
        PMIX_PROC_CREATE(procs, nprocs);
        if (NULL == procs) {
            rc = PMIX_ERR_NOMEM;
            goto error;
        }
        cnt = nprocs;
        PMIX_BFROPS_UNPACK(rc, peer, buf, procs, &cnt, PMIX_PROC);
        if (PMIX_SUCCESS != rc) {
            PMIX_ERROR_LOG(rc);
            PMIX_PROC_FREE(procs, nprocs);
            goto error;
        }
        /* sort the procs */
        qsort(procs, nprocs, sizeof(pmix_proc_t), pmix_util_compare_proc);
    } else {
        // this process is participating in a bootstrap
        // as an "add-member"
        bootstrap = true;
    }

    /* unpack the number of directives */
    cnt = 1;
    PMIX_BFROPS_UNPACK(rc, peer, buf, &ninf, &cnt, PMIX_SIZE);
    if (PMIX_SUCCESS != rc) {
        PMIX_ERROR_LOG(rc);
        goto error;
    }
    ninfo = ninf + 2;
    PMIX_INFO_CREATE(info, ninfo);
    /* store default response */
    rc = PMIX_SUCCESS;
    PMIX_INFO_LOAD(&info[ninf], PMIX_SORTED_PROC_ARRAY, NULL, PMIX_BOOL);
    PMIX_INFO_LOAD(&info[ninf+1], PMIX_LOCAL_COLLECTIVE_STATUS, &rc, PMIX_STATUS);
    if (0 < ninf) {
        cnt = ninf;
        PMIX_BFROPS_UNPACK(rc, peer, buf, info, &cnt, PMIX_INFO);
        if (PMIX_SUCCESS != rc) {
            PMIX_ERROR_LOG(rc);
            goto error;
        }
    }

    /* check directives */
    PMIX_CONSTRUCT(&xfer, pmix_list_t);
    for (n = 0; n < ninfo; n++) {
        if (PMIX_CHECK_KEY(&info[n], PMIX_GROUP_ASSIGN_CONTEXT_ID)) {
            need_cxtid = PMIX_INFO_TRUE(&info[n]);

        } else if (PMIX_CHECK_KEY(&info[n], PMIX_GROUP_LOCAL_ONLY)) {
            force_local = PMIX_INFO_TRUE(&info[n]);

        } else if (PMIX_CHECK_KEY(&info[n], PMIX_GROUP_BOOTSTRAP)) {
            // ignore the actual value - we just need to know it
            // is present
            bootstrap = true;

        } else if (PMIX_CHECK_KEY(&info[n], PMIX_TIMEOUT)) {
            PMIX_VALUE_GET_NUMBER(rc, &info[n].value, tv.tv_sec, uint32_t);
            if (PMIX_SUCCESS != rc) {
                PMIX_PROC_FREE(procs, nprocs);
                PMIX_INFO_FREE(info, ninfo);
                goto error;
            }

        }
        ncd = PMIX_NEW(pmix_info_caddy_t);
        ncd->info = &info[n];
        pmix_list_append(&xfer, &ncd->super);
    }
    // transfer the info
    ninf = pmix_list_get_size(&xfer);
    PMIX_INFO_CREATE(iptr, ninf);
    n = 0;
    PMIX_LIST_FOREACH(ncd, &xfer, pmix_info_caddy_t) {
        // avoid another copy operations
        memcpy(&iptr[n], ncd->info, sizeof(pmix_info_t));
        ++n;
    }
    // do not use PMIX_INFO_FREE here as we just want to
    // release the array, and not its contents
    free(info);
    info = iptr;
    ninfo = ninf;

    if (NULL == procs) {
        // this is a group member participating as an "add-member". Get
        // a separate tracker for each such participant
        trk = pmix_server_new_tracker(grpid, procs, nprocs, PMIX_GROUP_CONSTRUCT_CMD);
        if (NULL == trk) {
            /* only if a bozo error occurs */
            PMIX_ERROR_LOG(PMIX_ERROR);
            rc = PMIX_ERROR;
            free(grpid);
            goto error;
        }
        trk->collect_type = PMIX_COLLECT_YES;
        trk->grpop = PMIX_GROUP_CONSTRUCT;
        trk->info = info;
        trk->ninfo = ninfo;
        // grpid has been copied into the tracker
        free(grpid);

        /* add this contributor to the tracker so they get
         * notified when we are done */
        pmix_list_append(&trk->local_cbs, &cd->super);

        // this is a bootstrap, so pass it up
        goto proceed;
    }

    /* find/create the local tracker for this operation */
    trk = pmix_server_get_tracker(grpid, procs, nprocs, PMIX_GROUP_CONSTRUCT_CMD);
    if (NULL == trk) {
        /* If no tracker was found - create and initialize it once */
        trk = pmix_server_new_tracker(grpid, procs, nprocs, PMIX_GROUP_CONSTRUCT_CMD);
        if (NULL == trk) {
            /* only if a bozo error occurs */
            PMIX_ERROR_LOG(PMIX_ERROR);
            rc = PMIX_ERROR;
            free(grpid);
            goto error;
        }
        /* group members must have access to all endpoint info
         * upon completion of the construct operation */
        trk->collect_type = PMIX_COLLECT_YES;
        /* mark as being a construct operation */
        trk->grpop = PMIX_GROUP_CONSTRUCT;
        /* it is possible that different participants will
         * provide different attributes, so collect the
         * aggregate of them */
        rc = aggregate_info(trk, info, ninfo);
        if (PMIX_SUCCESS == rc) {
            // we extended the trk's info array
            PMIX_INFO_FREE(info, ninfo);
            info = NULL;
            ninfo = 0;
        }
        /* see if this constructor only references local processes and isn't
         * requesting a context ID - if both conditions are met, then we
         * can just locally process the request without bothering the host.
         * This is meant to provide an optimized path for a fairly common
         * operation */
        if (force_local) {
            trk->local = true;
        } else if (need_cxtid) {
            trk->local = false;
        } else {
            trk->local = true;
            for (n = 0; n < nprocs; n++) {
                /* if this entry references the local procs, then
                 * we can skip it */
                if (PMIX_RANK_LOCAL_PEERS == procs[n].rank ||
                    PMIX_RANK_LOCAL_NODE == procs[n].rank) {
                    continue;
                }
                /* see if it references a specific local proc */
                match = false;
                for (m = 0; m < pmix_server_globals.clients.size; m++) {
                    pr = (pmix_peer_t *) pmix_pointer_array_get_item(&pmix_server_globals.clients, m);
                    if (NULL == pr) {
                        continue;
                    }
                    if (PMIX_CHECK_NAMES(&procs[n], &pr->info->pname)) {
                        match = true;
                        break;
                    }
                }
                if (!match) {
                    /* this requires a non_local operation */
                    trk->local = false;
                    break;
                }
            }
        }
    } else {
        /* it is possible that different participants will
         * provide different attributes, so collect the
         * aggregate of them */
        rc = aggregate_info(trk, info, ninfo);
        if (PMIX_SUCCESS == rc) {
            // we extended the trk's info array
            PMIX_INFO_FREE(info, ninfo);
            info = NULL;
            ninfo = 0;
        }
    }
    // grpid has been copied into the tracker
    free(grpid);

    /* add this contributor to the tracker so they get
     * notified when we are done */
    pmix_list_append(&trk->local_cbs, &cd->super);

    // if this is a bootstrap, then pass it up
    if (bootstrap) {
        goto proceed;
    }

    /* are we locally complete? */
    if (trk->def_complete && pmix_list_get_size(&trk->local_cbs) == trk->nlocal) {
        locally_complete = true;
    }

    /* if we are not locally complete AND this operation
     * is completely local AND someone specified a timeout,
     * then we will monitor the timeout in this library.
     * Otherwise, any timeout must be done by the host
     * to avoid a race condition whereby we release the
     * tracker object while the host is still using it */
    if (!locally_complete && trk->local &&
        0 < tv.tv_sec && !trk->event_active) {
        PMIX_THREADSHIFT_DELAY(trk, grp_timeout, tv.tv_sec);
        trk->event_active = true;
    }

    /* if we are not locally complete, then we are done */
    if (!locally_complete) {
        return PMIX_SUCCESS;
    }

    /* if all local contributions have been received,
     * shutdown the timeout event if active */
    if (trk->event_active) {
        pmix_event_del(&trk->ev);
    }

    /* let the local host's server know that we are at the
     * "fence" point - they will callback once the barrier
     * across all participants has been completed */

    pmix_output_verbose(2, pmix_server_globals.group_output,
                        "local group op complete with %d procs",
                        (int) trk->npcs);

    if (trk->local) {
        /* we have created the local group, so we technically
         * are done. However, we want to give the host a chance
         * to know about the group to support further operations.
         * For example, a tool might want to query the host to get
         * the IDs of existing groups. So if the host supports
         * group operations, pass this one up to it but indicate
         * it is strictly local */
        if (NULL != pmix_host_server.group) {
            /* need to add an info indicating that this is strictly a local
             * operation, and any group info that was provided */
            if (!force_local) {
                /* add the local op flag and any grp info to the info array */
                ninfo = trk->ninfo + 1;
                PMIX_INFO_CREATE(info, ninfo);
                m = 0;
                for (n=0; n < trk->ninfo; n++) {
                    PMIX_INFO_XFER(&info[m], &trk->info[n]);
                    ++m;
                }
                PMIX_INFO_LOAD(&info[m], PMIX_GROUP_LOCAL_ONLY, NULL, PMIX_BOOL);
                PMIX_INFO_FREE(trk->info, trk->ninfo);
                trk->info = info;
                trk->ninfo = ninfo;
                info = NULL;
                ninfo = 0;
            }
            rc = pmix_host_server.group(PMIX_GROUP_CONSTRUCT, trk->id, trk->pcs, trk->npcs,
                                        trk->info, trk->ninfo, grpcbfunc, trk);
            if (PMIX_SUCCESS != rc) {
                if (PMIX_OPERATION_SUCCEEDED == rc) {
                    /* let the grpcbfunc threadshift the result */
                    grpcbfunc(PMIX_SUCCESS, NULL, 0, trk, NULL, NULL);
                    return PMIX_SUCCESS;
                }
                /* remove the tracker from the list */
                pmix_list_remove_item(&pmix_server_globals.collectives, &trk->super);
                PMIX_RELEASE(trk);
                return rc;
            }
            /* we will take care of the rest of the process when the
             * host returns our call */
            return PMIX_SUCCESS;
        } else {
            /* let the grpcbfunc threadshift the result */
            grpcbfunc(PMIX_SUCCESS, NULL, 0, trk, NULL, NULL);
            return PMIX_SUCCESS;
        }
    }

    /* we don't have to worry about the timeout event being
     * active in the rest of this code because we only come
     * here if the operation is NOT completely local, and
     * we only activate the timeout if it IS local */

proceed:
    /* check if our host supports group operations */
    if (NULL == pmix_host_server.group) {
        /* cannot support it */
        pmix_list_remove_item(&pmix_server_globals.collectives, &trk->super);
        PMIX_RELEASE(trk);
        return PMIX_ERR_NOT_SUPPORTED;
    }

    rc = pmix_host_server.group(PMIX_GROUP_CONSTRUCT, trk->id, trk->pcs, trk->npcs,
                                trk->info, trk->ninfo, grpcbfunc, trk);
    if (PMIX_SUCCESS != rc) {
        if (PMIX_OPERATION_SUCCEEDED == rc) {
            /* let the grpcbfunc threadshift the result */
            grpcbfunc(PMIX_SUCCESS, NULL, 0, trk, NULL, NULL);
            return PMIX_SUCCESS;
        }
        /* remove the tracker from the list */
        pmix_list_remove_item(&pmix_server_globals.collectives, &trk->super);
        PMIX_RELEASE(trk);
        return rc;
    }

    return PMIX_SUCCESS;

error:
    if (NULL != info) {
        PMIX_INFO_FREE(info, ninfo);
    }
    return rc;
}

/* we are being called from the PMIx server's switchyard function,
 * which means we are in an event and can access global data */
pmix_status_t pmix_server_grpdestruct(pmix_server_caddy_t *cd, pmix_buffer_t *buf)
{
    pmix_peer_t *peer = (pmix_peer_t *) cd->peer;
    int32_t cnt, m;
    pmix_status_t rc;
    char *grpid = NULL;
    pmix_info_t *info = NULL, *iptr;
    size_t n, ninfo, ninf, niptr;
    pmix_server_trkr_t *trk;
    pmix_proc_t *members = NULL;
    size_t nmembers = 0;
    bool force_local = false;
    bool match;
    bool locally_complete = false;
    pmix_peer_t *pr;
    struct timeval tv = {0, 0};

    pmix_output_verbose(2, pmix_server_globals.group_output,
                        "recvd grpdestruct cmd");

    /* unpack the group ID */
    cnt = 1;
    PMIX_BFROPS_UNPACK(rc, peer, buf, &grpid, &cnt, PMIX_STRING);
    if (PMIX_SUCCESS != rc) {
        PMIX_ERROR_LOG(rc);
        goto error;
    }

    /* is this a failed group? */
    if (NULL != pmix_server_globals.failedgrps) {
        for (m=0; NULL != pmix_server_globals.failedgrps[m]; m++) {
            if (0 == strcmp(grpid, pmix_server_globals.failedgrps[m])) {
                /* yes - reject it */
                free(grpid);
                return PMIX_ERR_TIMEOUT;
            }
        }
    }

    /* unpack the number of members */
    cnt = 1;
    PMIX_BFROPS_UNPACK(rc, peer, buf, &nmembers, &cnt, PMIX_SIZE);
    if (PMIX_SUCCESS != rc) {
        PMIX_ERROR_LOG(rc);
        goto error;
    }
    if (0 == nmembers) {
        /* not allowed */
        rc = PMIX_ERR_BAD_PARAM;
        goto error;
    }
    /* unpack the membership */
    PMIX_PROC_CREATE(members, nmembers);
    cnt = nmembers;
    PMIX_BFROPS_UNPACK(rc, peer, buf, members, &cnt, PMIX_PROC);
    if (PMIX_SUCCESS != rc) {
        PMIX_ERROR_LOG(rc);
        PMIX_PROC_FREE(members, nmembers);
        goto error;
    }

    /* unpack the number of directives */
    cnt = 1;
    PMIX_BFROPS_UNPACK(rc, peer, buf, &ninf, &cnt, PMIX_SIZE);
    if (PMIX_SUCCESS != rc) {
        PMIX_ERROR_LOG(rc);
        goto error;
    }
    ninfo = ninf + 1;
    PMIX_INFO_CREATE(info, ninfo);
    /* store default response */
    rc = PMIX_SUCCESS;
    PMIX_INFO_LOAD(&info[ninf], PMIX_LOCAL_COLLECTIVE_STATUS, &rc, PMIX_STATUS);
    if (0 < ninf) {
        cnt = ninf;
        PMIX_BFROPS_UNPACK(rc, peer, buf, info, &cnt, PMIX_INFO);
        if (PMIX_SUCCESS != rc) {
            PMIX_ERROR_LOG(rc);
            goto error;
        }
    }

    /* check directives */
    for (n = 0; n < ninfo; n++) {
        if (PMIX_CHECK_KEY(&info[n], PMIX_GROUP_LOCAL_ONLY)) {
            force_local = PMIX_INFO_TRUE(&info[n]);
        } else if (PMIX_CHECK_KEY(&info[n], PMIX_GROUP_LOCAL_ONLY)) {
            force_local = PMIX_INFO_TRUE(&info[n]);
        } else if (PMIX_CHECK_KEY(&info[n], PMIX_TIMEOUT)) {
            PMIX_VALUE_GET_NUMBER(rc, &info[n].value, tv.tv_sec, uint32_t);
            if (PMIX_SUCCESS != rc) {
                return rc;
            }
        }
    }

    /* find/create the local tracker for this operation */
    trk = pmix_server_get_tracker(grpid, members, nmembers, PMIX_GROUP_DESTRUCT_CMD);
    if (NULL == trk) {
        /* If no tracker was found - create and initialize it once */
        trk = pmix_server_new_tracker(grpid, members, nmembers, PMIX_GROUP_DESTRUCT_CMD);
        if (NULL == trk) {
            /* only if a bozo error occurs */
            PMIX_ERROR_LOG(PMIX_ERROR);
            rc = PMIX_ERROR;
            free(grpid);
            goto error;
        }
        trk->collect_type = PMIX_COLLECT_NO;
        /* mark as being a destruct operation */
        trk->grpop = PMIX_GROUP_DESTRUCT;
        /* see if this destructor only references local processes */
        trk->local = true;
        for (n = 0; n < nmembers; n++) {
            /* if this entry references the local procs, then
             * we can skip it */
            if (PMIX_RANK_LOCAL_PEERS == members[n].rank ||
                PMIX_RANK_LOCAL_NODE == members[n].rank) {
                continue;
            }
            /* see if it references a specific local proc - note that
             * the member name could include rank=wildcard */
            match = false;
            for (m = 0; m < pmix_server_globals.clients.size; m++) {
                pr = (pmix_peer_t *) pmix_pointer_array_get_item(&pmix_server_globals.clients, m);
                if (NULL == pr) {
                    continue;
                }
                // cannot use PMIX_CHECK_PROCID here as pmix_peer_t includes a pname field
                // and not a pmix_proc_t
                if (PMIX_RANK_WILDCARD == members[n].rank ||
                    PMIX_RANK_WILDCARD == pr->info->pname.rank) {
                    if (PMIX_CHECK_NSPACE(members[n].nspace, pr->info->pname.nspace)) {
                        match = true;
                        break;
                    }
                }
                if (PMIX_CHECK_NAMES(&members[n], &pr->info->pname)) {
                    match = true;
                    break;
                }
            }
            if (!match) {
                /* this requires a non_local operation */
                trk->local = false;
                break;
            }
        }
    }
    // grpid has been copied into the tracker
    free(grpid);

    /* it is possible that different participants will
     * provide different attributes, so collect the
     * aggregate of them */
    if (NULL == trk->info) {
        trk->info = info;
        trk->ninfo = ninfo;
    } else {
        niptr = trk->ninfo + ninfo;
        PMIX_INFO_CREATE(iptr, niptr);
        for (n=0; n < trk->ninfo; n++) {
            PMIX_INFO_XFER(&iptr[n], &trk->info[n]);
        }
        for (n=0; n < ninfo; n++) {
            PMIX_INFO_XFER(&iptr[n+trk->ninfo], &info[n]);
        }
        PMIX_INFO_FREE(trk->info, trk->ninfo);
        trk->info = iptr;
        trk->ninfo = niptr;
        /* cleanup */
        PMIX_INFO_FREE(info, ninfo);
        info = NULL;
    }

    /* add this contributor to the tracker so they get
     * notified when we are done */
    pmix_list_append(&trk->local_cbs, &cd->super);

    /* are we locally complete? */
    if (trk->def_complete && pmix_list_get_size(&trk->local_cbs) == trk->nlocal) {
        locally_complete = true;
    }

    /* if we are not locally complete AND this operation
     * is completely local AND someone specified a timeout,
     * then we will monitor the timeout in this library.
     * Otherwise, any timeout must be done by the host
     * to avoid a race condition whereby we release the
     * tracker object while the host is still using it */
    if (!locally_complete && trk->local &&
        0 < tv.tv_sec && !trk->event_active) {
        PMIX_THREADSHIFT_DELAY(trk, grp_timeout, tv.tv_sec);
        trk->event_active = true;
    }

    /* if we are not locally complete, then we are done */
    if (!locally_complete) {
        return PMIX_SUCCESS;
    }

    /* if all local contributions have been received,
     * shutdown the timeout event if active */
    if (trk->event_active) {
        pmix_event_del(&trk->ev);
    }

    /* let the local host's server know that we are at the
     * "fence" point - they will callback once the barrier
     * across all participants has been completed */
    pmix_output_verbose(2, pmix_server_globals.group_output,
                        "local group destruct complete %d",
                        (int) trk->nlocal);
    if (trk->local) {
        /* we have removed the local group, so we technically
         * are done. However, we want to give the host a chance
         * to know remove the group to support further operations.
         * For example, a tool might want to query the host to get
         * the IDs of existing groups. So if the host supports
         * group operations, pass this one up to it but indicate
         * it is strictly local */
        if (NULL != pmix_host_server.group) {
            /* we only need to pass the group ID, members, and
             * an info indicating that this is strictly a local
             * operation */
            if (!force_local) {
                /* add the local op flag to the info array */
                ninfo = trk->ninfo + 1;
                PMIX_INFO_CREATE(info, ninfo);
                for (n=0; n < trk->ninfo; n++) {
                    PMIX_INFO_XFER(&info[n], &trk->info[n]);
                }
                PMIX_INFO_LOAD(&info[trk->ninfo], PMIX_GROUP_LOCAL_ONLY, NULL, PMIX_BOOL);
                PMIX_INFO_FREE(trk->info, trk->ninfo);
                trk->info = info;
                trk->ninfo = ninfo;
                info = NULL;
                ninfo = 0;
            }
            rc = pmix_host_server.group(PMIX_GROUP_DESTRUCT, trk->id,
                                        members, nmembers,
                                        trk->info, trk->ninfo, grpcbfunc, trk);
            if (PMIX_SUCCESS != rc) {
                if (PMIX_OPERATION_SUCCEEDED == rc) {
                    /* let the grpcbfunc threadshift the result */
                    grpcbfunc(PMIX_SUCCESS, NULL, 0, trk, NULL, NULL);
                    PMIX_PROC_FREE(members, nmembers);
                    return PMIX_SUCCESS;
                }
            }
            /* we will take care of the rest of the process when the
             * host returns our call */
            return PMIX_SUCCESS;
        } else {
            /* let the grpcbfunc threadshift the result and remove
             * the group from our list */
            grpcbfunc(PMIX_SUCCESS, NULL, 0, trk, NULL, NULL);
            PMIX_PROC_FREE(members, nmembers);
            return PMIX_SUCCESS;
        }
    }

    /* this operation requires global support, so check if our host
     * supports group operations */
    if (NULL == pmix_host_server.group) {
        /* cannot support it */
        pmix_list_remove_item(&pmix_server_globals.collectives, &trk->super);
        PMIX_RELEASE(trk);
        PMIX_PROC_FREE(members, nmembers);
        return PMIX_ERR_NOT_SUPPORTED;
    }

    rc = pmix_host_server.group(PMIX_GROUP_DESTRUCT, trk->id,
                                members, nmembers,
                                trk->info, trk->ninfo, grpcbfunc, trk);
    if (PMIX_SUCCESS != rc) {
        if (PMIX_OPERATION_SUCCEEDED == rc) {
            /* let the grpcbfunc threadshift the result */
            grpcbfunc(PMIX_SUCCESS, NULL, 0, trk, NULL, NULL);
            PMIX_PROC_FREE(members, nmembers);
            return PMIX_SUCCESS;
        }
        /* remove the tracker from the list */
        pmix_list_remove_item(&pmix_server_globals.collectives, &trk->super);
        PMIX_RELEASE(trk);
        PMIX_PROC_FREE(members, nmembers);
        return rc;
    }

    PMIX_PROC_FREE(members, nmembers);
    return PMIX_SUCCESS;

error:
    if (NULL != info) {
        PMIX_INFO_FREE(info, ninfo);
    }
    if (NULL != members) {
        PMIX_PROC_FREE(members, nmembers);
    }
    return rc;
}
