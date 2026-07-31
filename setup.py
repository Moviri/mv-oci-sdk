# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

import io
import os
import re

from setuptools import setup, find_packages


def open_relative(*path):
    """
    Opens files in read-only with a fixed utf-8 encoding.

    All locations are relative to this setup.py file.
    """
    here = os.path.abspath(os.path.dirname(__file__))
    filename = os.path.join(here, *path)
    return io.open(filename, mode="r", encoding="utf-8")


with open_relative("src", "oci", "version.py") as fd:
    version = re.search(
        r"^__version__\s*=\s*['\"]([^'\"]*)['\"]",
        fd.read(), re.MULTILINE).group(1)
    if not version:
        raise RuntimeError("Cannot find version information")

with open_relative("README.rst") as f:
    readme = f.read()

requires = [
    "certifi",
    "cryptography>=46.0.5,<50.0.0",
    "pyOpenSSL>=26.0.0,<27.0.0",
    "python-dateutil>=2.5.3,<3.0.0",
    "pytz>=2016.10",
    "circuitbreaker>=1.3.1,<3.0.0",
    "urllib3>=2.6.3",
    "PyJWT>=2.12.0",
    "crc32c==2.8.0",
]

setup(
    name="mv-oci-sdk",
    url="https://github.com/Moviri/mv-oci-sdk",
    version=version,
    description="Moviri-maintained OCI SDK runtime curated exclusively for python-oci-compute",
    long_description=readme,
    long_description_content_type="text/x-rst",
    author="Moviri",
    author_email="dynatrace_extensions@moviri.com",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    include_package_data=True,
    install_requires=requires,
    python_requires=">=3.10",
    license="Universal Permissive License 1.0 or Apache License 2.0",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "License :: OSI Approved :: Universal Permissive License (UPL)",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
    ]
)
