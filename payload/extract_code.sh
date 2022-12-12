#!/bin/bash

if [ -f "$1" ] ; then
	objdump -d "$1" | grep '[0-9a-f]:'| grep -v 'file' | cut -f2 -d: | cut -f1-6 -d' '| tr -s ' '| tr '\t' ' ' | sed 's/ $//g' | sed 's/ /, 0x/g' | paste -d '' -s | sed 's/, //1'
else
	printf "Usage: bash extract_code.sh [file]\n"
fi
