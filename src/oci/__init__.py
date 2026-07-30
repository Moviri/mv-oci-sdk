# coding: utf-8
# Copyright (c) 2016, 2026, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

import os
import sys

from . import (
    auth,
    circuit_breaker,
    config,
    constants,
    decorators,
    developer_tool_configuration,
    exceptions,
    fips,
    pagination,
    regions,
    retry,
)
from .base_client import BaseClient
from .request import Request
from .response import Response
from .signer import Signer
from .version import __version__  # noqa
from .waiter import wait_until


fips.enable_fips_mode()

_COMMON_EXPORTS = [
    "BaseClient",
    "Request",
    "Response",
    "Signer",
    "config",
    "constants",
    "decorators",
    "exceptions",
    "regions",
    "wait_until",
    "pagination",
    "auth",
    "retry",
    "fips",
    "circuit_breaker",
    "developer_tool_configuration",
]

_RETAINED_SERVICES = [
    "core",
    "database",
    "database_management",
    "database_tools",
    "dns",
    "file_storage",
    "functions",
    "identity",
    "load_balancer",
    "monitoring",
    "network_load_balancer",
    "object_storage",
    "queue",
    "work_requests",
]

if os.getenv("OCI_PYTHON_SDK_NO_SERVICE_IMPORTS", "").lower() not in ["true", "1"]:
    __all__ = _COMMON_EXPORTS + _RETAINED_SERVICES

    if (
        sys.version_info >= (3, 7)
        and os.getenv("OCI_PYTHON_SDK_LAZY_IMPORTS_DISABLED", "False").lower()
        != "true"
    ):

        def __getattr__(name):
            if name in _RETAINED_SERVICES:
                import importlib

                return importlib.import_module(__name__ + "." + name)
            raise AttributeError("module {} has no attribute {}".format(__name__, name))

    else:
        from . import (  # noqa: F401
            core,
            database,
            database_management,
            database_tools,
            dns,
            file_storage,
            functions,
            identity,
            load_balancer,
            monitoring,
            network_load_balancer,
            object_storage,
            queue,
            work_requests,
        )
