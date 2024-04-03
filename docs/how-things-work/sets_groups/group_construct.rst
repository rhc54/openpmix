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
