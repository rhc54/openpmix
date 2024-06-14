Group Construction
==================

PMIx supports two slightly related, but functionally different concepts
known as *process sets* and *process groups*. This section defines
these two concepts and describes how they are utilized, along with their
corresponding APIs.


Collective Method
-----------------

All participants know the ID of all other participants, and thus call
``PMIx_Group_construct`` with the array of all participating proc IDs.

Host responsibilities
^^^^^^^^^^^^^^^^^^^^^

Perform collective allgather operation across participants


Bootstrap Method
----------------
Bootstrap is used when the processes involved in group construct do
not know the identity of all other processes that will be participating.
It is required, however, that all participants at least know how many
processes will be participating.

In this context, participants equate to processes that call ``PMIx_Group_construct`` (or
its non-blocking equivalent) and pass _only_ their own process identifier
to the ``procs`` argument. Participants are _required_ to include the
``PMIX_GROUP_BOOTSTRAP`` attribute in their array of ``pmix_info_t``
directives, with the value in that attribute set to equal the number
of participants in the group construct operation.

Add Members
-----------
Additional group members can be specified by any participant via the ``PMIX_GROUP_ADD_MEMBERS``
attribute. The PMIx server library and host are jointly responsible for aggregating the
additional group members specified across participants. Processes that are on the
"additional member" list must call ``PMIx_Group_construct``
with a ``NULL`` ``procs`` argument - this indicates that the process is to
be added to the group (via PMIx event, internal to the ``PMIx_Group_construct`` function)
when the group construct operation has completed.

Participant in this context equates to any process that calls ``PMIx_Group_construct``,
whether bootstrapping or not.

Note that the group construct operation _cannot_ complete until all "add members" have
called ``PMIx_Group_construct``. This is required so that any group and/or endpoint information
provided by the added members can be included in the returned ``pmix_info_t`` array.
