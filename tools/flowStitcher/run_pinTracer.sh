#!/bin/sh
## usage: ./run_pinTracer.sh ./tests/test_addrleak  ./tests/in0

tmp=$(mktemp)

DEBUG="0"

MY_BUILD_DIR="XXX_MY_BUILD_DIR"

PIN=$MY_BUILD_DIR/pin-2.14-71313-gcc.4.4.7-linux/pin

FLOWSTITCHER=./flowStitcher.so
#FLOWSTITCHER=/ext4-384G/Experiments/vineBAP/build/tools/flowStitcher/flowStitcher.so


PROG="$(which $1)"
BASE_PROG=$(basename "$PROG")
OUT_GRAPH_DIR="$BASE_PROG.dots"

PT_ARGS="--skiplibs=0 --debug=$DEBUG --outprog=$tmp --dot=$OUT_GRAPH_DIR $STATIC"


if [ -d "$OUT_GRAPH_DIR" ]; then
    echo "ah, exist !"
    rm -rf "$OUT_GRAPH_DIR"
fi

mkdir $OUT_GRAPH_DIR


## shift 1: 让原来的 $4 现在变成 $3
shift 1

export LD_BIND_NOW=1
cmd=$PIN" -ifeellucky -injection child -t "$FLOWSTITCHER" "$PT_ARGS" -- ""$PROG"" ""$*"
echo "cmd: "$cmd

#$PIN -appdebug -ifeellucky -injection child -t $FLOWSTITCHER $PT_ARGS -- $PROG < $*
$PIN -ifeellucky -injection child -t $FLOWSTITCHER $PT_ARGS -- $PROG < $*

ret=$?

if [ $ret -eq 0 ]
then
	EXT="cfg"
	OUTFILE="$BASE_PROG.$EXT"
	mv -f "$tmp" "$OUTFILE" 

else
	echo "FATAL ERROR: execution failed !"
fi
