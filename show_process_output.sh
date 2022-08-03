#!/bin/bash
pid=$1
strace -e trace=write -s9999 -fp $pid 2>&1 | grep --line-buffered '^write' | grep -o '".\+[^"]"'