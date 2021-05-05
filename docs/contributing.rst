Contributing to PMIx
========================

.. JMS How can I create a TOC just for this page here at the top?

/////////////////////////////////////////////////////////////////////////

Can I contribute to PMIx?
-----------------------------

**YES!**

There are many ways to contribute.  Here are a few:

#. Subscribe to `the mailing lists=
   <https://groups.google.com/g/pmix>`_ and become active in
   the discussions.
#. Community members meet every Thursday at noon US Pacific for
   a telecon to discuss the implementation. Anyone is welcome
   to attend.
#. Obtain `a Git clone <https://github.com/openpmix/openpmix>`_ of
   PMIx's code base and start looking through the code. it is usually
   better to work with the most recent development version of the
   repository than the last stable release (especially for new projects).
   Contributions are submitted via pull requests against the target
   repository on Github. All commits must contain a “Signed-off-by”
   token in the commit message. This constitutes your agreement with
   the OpenPMIx Contributor’s Declaration.

   * Be sure to see the :doc:`Developers guide </developers>` for
     technical details about the code base and how to build it).

#. Write your own components and contribute them back to the main code
   base.
#. Contribute bug fixes and feature enhancements to the main code
   base.
#. Provide testing resources:

   #. For Github Pull Request Continuous Integration (CI)
   #. For nightly snapshot builds and testing


/////////////////////////////////////////////////////////////////////////

I found a bug!  How do I report it?
-----------------------------------

First check that this is not already a known issue by checking the `issues
<https://github.com/openpmix/openpmix/issues>`_ posted on the repository.
If you can't find your
problem mentioned anywhere, it is most helpful if you can create a
"recipe" to replicate the bug.

Please see the :doc:`Getting Help </getting-help>`_ page for more details on
submitting bug reports.


/////////////////////////////////////////////////////////////////////////

What if I don't want my contribution to be free / open source?
--------------------------------------------------------------

No problem.

While we are creating free / open-source software, and we would prefer
if everyone's contributions to PMIx were also free / open-source,
we certainly recognize that other organizations have different goals
from us.  Such is the reality of software development in today's
global economy.

As such, it is perfectly acceptable to make non-free / non-open-source
contributions to PMIx.

We obviously cannot accept such contributions into the main code base,
but you are free to distribute plugins, enhancements, etc. as you see
fit.  Indeed, the :doc:`the BSD license </license>` is extremely
liberal in its redistribution provisions.


/////////////////////////////////////////////////////////////////////////

I want to fork the PMIx code base.  Can I?
----------------------------------------------

Yes... but we'd prefer if you didn't.

Although :doc:`PMIx's license </license>` allows third parties to
fork the code base, we would strongly prefer if you did not.  Forking
is not necessarily a Bad Thing, but history has shown that creating
too many forks leads to massive user and system
administrator confusion.

If you're thinking of forking the PMIx code base, please let us
know -- let's see if we can work something out so that it is not
necessary.


/////////////////////////////////////////////////////////////////////////

Rats!  My contribution was not accepted into the main PMIx code base.  What now?
------------------------------------------------------------------------------------

If your contribution was not accepted into the main PMIx
code base, there are likely to be good reasons for it (perhaps
technical, perhaps due to licensing restrictions, etc.).

If you wrote a standalone component, you can still distribute this
component independent of the main PMIx distribution.  PMIx
components can be installed into existing PMIx installations.  As
such, you can distribute your component -- even if it is closed source
(e.g., distributed as binary-only) -- via any mechanism you choose,
such as on a web site, FTP site, etc.
