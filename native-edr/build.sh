#!/usr/bin/env bash
set -euo pipefail

CXX=clang++
STD="-std=c++20"
FLAGS="-Wall -Wextra -O2"
INCLUDES="-Ilogging -Igcore"

mkdir -p build

$CXX $STD $FLAGS $INCLUDES -c logging/logging.cpp  -o build/logging.o
$CXX $STD $FLAGS $INCLUDES -c gcore/gcore.cpp       -o build/gcore.o
$CXX $STD $FLAGS $INCLUDES -c fanotify/fanotify.cpp -o build/fanotify.o
$CXX $STD $FLAGS $INCLUDES -c dpi/dpi.cpp           -o build/dpi.o
$CXX $STD $FLAGS $INCLUDES -c kdetect/kdetect.cpp   -o build/kdetect.o
$CXX $STD $FLAGS $INCLUDES -Iyara -c yara/yara.cpp  -o build/yara.o

$CXX $STD $FLAGS $INCLUDES \
    build/logging.o build/gcore.o build/fanotify.o \
    build/dpi.o build/kdetect.o build/yara.o \
    main.cpp -o build/edr -lpcap


$CXX $STD $FLAGS -c test/fake_client.cpp -o build/edr_test.o
$CXX $STD $FLAGS build/edr_test.o -o build/edr_test

echo "Build OK "
