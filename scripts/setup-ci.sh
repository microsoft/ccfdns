#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -ex

tdnf -y install zlib-devel  \
    clang-tools-extra  \
    glibc-devel  \
    glibc-static  \
    python3  \
    python-pip  \
    git  \
    npm