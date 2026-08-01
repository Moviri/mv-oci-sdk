Moviri OCI SDK runtime for python-oci-compute
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

About
=====

``mv-oci-sdk`` is a Moviri-maintained, consumer-exclusive runtime curated for
``python-oci-compute``. It is derived from the `Oracle Cloud Infrastructure
Python SDK`_ but intentionally packages only the OCI services and shared
runtime dependencies used by that Dynatrace extension.

Python 3.10, 3.11, 3.12, 3.13, and 3.14 are the tested support matrix. Package
metadata permits installation on Python 3.10 or newer so a newly released
Python version can be evaluated without an artificial installation cap.

Supported public services
=========================

The supported public service surface is exactly:

* ``core``
* ``file_storage``
* ``functions``
* ``identity``
* ``load_balancer``
* ``monitoring``
* ``network_load_balancer``
* ``object_storage``

DNS models are retained only as an internal pagination dependency. The DNS
client is not packaged or supported.

Other OCI services are not packaged or supported. The standalone waiter,
generated composite-operation wrappers, Functions Invoke client, and Object
Storage transfer helpers are also excluded. Oracle examples or API-reference
pages that depend on an excluded service or helper do not apply unchanged to
this distribution.

Installation
============

Use a Python virtual environment and install the Moviri distribution:

::

    pip install mv-oci-sdk

This distribution installs the ``oci`` import package. Do not install the
official ``oci`` distribution into the same environment.

Usage
=====

Use the retained clients with the normal OCI configuration and signing
concepts. For example:

.. code-block:: python

    import oci

    config = oci.config.from_file("~/.oci/config", "DEFAULT")
    identity = oci.identity.IdentityClient(config)
    tenancy = identity.get_tenancy(config["tenancy"]).data

Oracle's documentation remains useful for general OCI authentication,
configuration, and retained-service concepts. It describes the complete
Oracle SDK, however, so verify that an example uses only the supported surface
listed above.

Attribution and license
=======================

This curated runtime is derived from Oracle's open-source OCI Python SDK and
retains Oracle copyright, license, and third-party notices. Oracle does not
maintain this Moviri distribution.

The source is available under the Universal Permissive License (UPL) 1.0 or
Apache License 2.0 as described in ``LICENSE.txt``.

.. _Oracle Cloud Infrastructure Python SDK: https://github.com/oracle/oci-python-sdk
