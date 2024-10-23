# C Language Compiler in Linux

This project is a basic compiler written in C for Linux. It consists of a scanner (scanner.l) and a parser (Parser.y) which are built using Lex and Yacc respectively. A shell script (run_compiler.sh) automates the compilation and execution process.

### ⭐ Files:

1. Parser.y: Yacc file containing the grammar rules and parser logic.

2. scanner.l: Lex file for lexical analysis (scanner).

3. lex.yy.c: Automatically generated C source file by Lex for the scanner.

4. run_compiler.sh: Shell script to compile the Lex and Yacc files and run the compiler.

5. input_file.txt: Example input file to feed into the compiler.

### ⭐ Requirements:

1. Lex: A tool for generating scanners (lexical analyzers).

2. Yacc: A tool for generating parsers based on grammar rules.

3. GCC: The GNU Compiler Collection, used to compile the generated C files.

Make sure you have these tools installed on your Linux system.

### ⭐ To run the compiler, follow these steps:

1. git clone https://github.com/LiorDaichman/C-Compiler-in-Linux

2. cd C-Compiler-in-Linux

3. Run the script with an input file: ./run_compiler.sh input_file.txt
