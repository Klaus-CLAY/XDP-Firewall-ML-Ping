#!/bin/bash
pid=$1
strace -e trace=write -s9999 -fp $pid 2>&1 | sed -u -n '/^write/p' | sed -u 's/^[^"]*"\([^"]*\)".*/\1/'