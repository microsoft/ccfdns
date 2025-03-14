#!/bin/sh
cd build
CC=clang-15 CXX="clang++-15" cmake -GNinja .. -DTRACE_LOGGING=ON
ninja

