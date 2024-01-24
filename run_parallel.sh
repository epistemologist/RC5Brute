#!/bin/bash
set -e

NUM_CORES=6
for a in $(seq 0 $NUM_CORES 256); do
	b=$(($a+$NUM_CORES>256 ? 256 : $a+$NUM_CORES))
	for first_byte in $(seq $a $b); do
		(echo $first_byte | ./worker > "tmp$i.txt") &
	done
	wait
	cat tmp*.txt > "out$a.txt"
	rm tmp*.txt
done
