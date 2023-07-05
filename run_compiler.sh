#!/bin/bash

# Check if the input file is provided
if [ -z "$1" ]; then
    echo "Usage: ./run_compiler.sh <input_file.txt>"
    exit 1
fi

input_file=$1

clear
lex scanner.l
yacc -d Parser.y
gcc -o compiler lex.yy.c y.tab.c
./compiler < "$input_file"
