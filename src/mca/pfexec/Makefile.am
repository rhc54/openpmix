#
# Copyright (c) 2004-2005 The Trustees of Indiana University and Indiana
#                         University Research and Technology
#                         Corporation.  All rights reserved.
# Copyright (c) 2004-2005 The University of Tennessee and The University
#                         of Tennessee Research Foundation.  All rights
#                         reserved.
# Copyright (c) 2004-2005 High Performance Computing Center Stuttgart,
#                         University of Stuttgart.  All rights reserved.
# Copyright (c) 2004-2005 The Regents of the University of California.
#                         All rights reserved.
# Copyright (c) 2010      Cisco Systems, Inc.  All rights reserved.
# Copyright (c) 2019      Intel, Inc.  All rights reserved.
# Copyright (c) 2022-2024 Nanook Consulting  All rights reserved.
# $COPYRIGHT$
#
# Additional copyrights may follow
#
# $HEADER$
#

# main library setup
noinst_LTLIBRARIES = libmca_pfexec.la
libmca_pfexec_la_SOURCES =

# pkgdata setup
dist_pmixdata_DATA =

# local files
headers = pfexec.h \
		  pfexec_types.h
libmca_pfexec_la_SOURCES += $(headers)

# install the header files
pmixdir = $(pmixincludedir)/$(subdir)
nobase_pmix_HEADERS = $(headers)

include base/Makefile.am

distclean-local:
	rm -f base/static-components.h
