#!/bin/sh

cd llvm-build
make -f ../llvm-Makefile
echo $(pwd)
make
