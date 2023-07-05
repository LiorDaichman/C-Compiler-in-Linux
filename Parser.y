%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h> 
#include <stdbool.h>
#include <stddef.h>
#define MAX_ID_LENGTH 256
#define MAX_SYMBOL_ENTRIES 10000
int Count1 = 0;
int Count2 = 0;

typedef struct node {
	char *token; 
	struct node *left;
	struct node *right;
} node;

typedef struct SymbolEntry {
    char* name;
    char* type;
    bool isDefined;       // For functions
    bool isInitialized;   // For variables
    struct SymbolEntry *next;
} SymbolEntry;

SymbolEntry symbolTable[MAX_SYMBOL_ENTRIES];
struct node* mknode(char* token, node* left, node* right);
int printtree(node* tree);
void printTab();
void printTabs();
void freeAST(node* tree);
void freeNode(node* node);
bool insertSymbolEntry(char* name, char* type);
int insertSymbolEntrycheck(char *name, char *type);
bool insertSymbolEntrycheckdefine(char* name, char* type);
bool checkArguments(char* functionName, int numArguments);
int yylex(void);
void yyerror(const char *s);
int symbolTableIndex = 0;
int symbolTableIndexcheck = 0;
size_t symbolCount = 0;
extern int yylineno;
extern char *yytext;
int yydebug = 0;
%}

%union {
  char *str;
  struct node *node;
}

%token <str> BOOL CHAR INT REAL STRING INTPTR CHARPTR REALPTR VAR VOID FUNCTION
%token <str> NULLL RETURN TRUE FALSE IF ELSE WHILE FOR DO IDENTIFIER INTEGER
%token <str> AND EQL BIGGEREQL SMALLEREQL
%token <str> NOTEQL OR
%token <str> NUMVAL ID INTVAL REALVAL CHARVAL STRINGVAL 
%token <str> ARG COMMENTS
%type <node> PROGRAM FUNCS FUNC PROC ARGS BODY TYPE INPUT STMTS LENGTH
%type <node> VAR_ASSIGN EXP STMT IF_ST BLOCK_OP ELSE_ COND LOOP VAR_ ARR_LHS RETURN_STMT 
%type <node> VAR_DEC VAR_LHS RHS ARG_INPUTS VAR_NEST ARR_VAR ARR_ASSIGN POINTER ARGS_SECTION FUNC_
%left '+' '-'
%left '*' '/'
%left UNARY_MINUS
%%
S: PROGRAM {printtree($1);};

PROGRAM: FUNCS   {$$ = mknode("CODE", $1, NULL);} , declaration_list {printtree($1);freeAST($1);};

declaration_list: declaration_list declaration
                | declaration
                ;

declaration: var_declaration
            | fun_declaration
            ;
            var_declaration: type_specifier IDENTIFIER ';' {
    if (insertSymbolEntrycheck(yytext, $1)) {
        printTab();
        printf("Variable Declaration: %s\n", yytext);
    } else {
        yyerror("Variable already declared");
    }
}

fun_declaration: type_specifier IDENTIFIER '(' params ')' compound_stmt {
    if (insertSymbolEntrycheck(yytext, $1)) {
        printTab();
        printf("Function Declaration: %s\n", yytext);
        increaseIndent();
    } else {
        yyerror("Function already declared");
    }
}

params: param_list
        |
        ;

param_list: param_list ',' param
            | param
            ;

param: type_specifier IDENTIFIER {
    if (insertSymbolEntrycheck(yytext, $1)) {
        printTab();
        printf("Parameter: %s\n", yytext);
    } else {
        yyerror("Parameter already declared");
    }
}

ype_specifier: INT
                | VOID
                ;

compound_stmt: '{' local_declarations statement_list '}' {
    decreaseIndent();
}

local_declarations: local_declarations var_declaration
                    |
                    ;

statement_list: statement_list statement
                |
                ;

statement: expression_stmt
            | compound_stmt
            | selection_stmt
            | iteration_stmt
            | return_stmt
            ;

expression_stmt: expression ';' {
    printTab();
    printf("Expression Statement\n");
}

selection_stmt: IF '(' expression ')' statement {
    printTab();
    printf("If Statement\n");
    increaseIndent();
} ELSE statement {
    decreaseIndent();
}

iteration_stmt: WHILE '(' expression ')' statement {
    printTab();
    printf("While Statement\n");
    increaseIndent();
}

return_stmt: RETURN ';' {
    printTab();
    printf("Return Statement\n");
}
            | RETURN expression ';' {
    printTab();
    printf("Return Statement\n");
}

expression: var '=' expression {
    printTab();
    printf("Assignment Expression: %s\n", $1);
}
            | simple_expression {
    printTab();
    printf("Simple Expression\n");
}
            ;

var: IDENTIFIER {
    if (lookupSymbolEntry(yytext)) {
        printTab();
        printf("Variable: %s\n", yytext);
    } else {
        yyerror("Variable not declared");
    }
}

simple_expression: additive_expression relop additive_expression
                    | additive_expression
                    ;
                    
                    relop: '<'
        | LESSEQ
        | '>'
        | GREATEREQ
        | EQ
        | NEQ
        ;

additive_expression: additive_expression addop term
                    | term
                    ;

addop: '+'
        | '-'
        ;

term: term mulop factor
    | factor
    ;

mulop: '*'
        | '/'
        ;

factor: '(' expression ')'
        | var
        | call
        | NUM {
            printTab();
            printf("Number: %s\n", yytext);
        }
        ;

call: IDENTIFIER '(' args ')' {
    if (checkArguments(yytext, $3)) {
        printTab();
        printf("Function Call: %s\n", yytext);
    } else {
        yyerror("Invalid number of arguments");
    }
}

args: arg_list
    |
    ;

arg_list: arg_list ',' expression
        | expression
        ;

FUNCS: FUNC FUNCS       {$$ = mknode(NULL, $1, $2); }
     | PROC FUNCS       {$$ = mknode(NULL, $1, $2); }
     | FUNC             {$$ = mknode(NULL, $1, NULL);}
     | PROC             {$$ = mknode(NULL, $1, NULL);};


PROC: FUNCTION INPUT '(' ARGS  ')' ':' VOID '{' BODY '}'      { $$ = mknode("PROC", mknode( NULL, mknode( NULL, mknode( $2->token, NULL, NULL), mknode( "ARGS", $4, NULL)), mknode( NULL, mknode( "RET VOID", NULL, NULL), mknode("BODY", $9, NULL))), mknode(NULL, NULL, NULL));};
 
FUNC: FUNCTION INPUT '(' ARGS ')' ':' TYPE '{' BODY '}'    
{
	  char *retType = malloc(strlen("RET") + strlen($7->token) + 1);
	  
      strcpy(retType, "RET ");
      strcat(retType, $7->token);
          // Check for duplicate function names
    if (!insertSymbolEntry($2->token, retType)) {
        free(retType); // Free the allocated memory
        YYERROR;
    }
        if (!insertSymbolEntrycheck($2->token, retType)) {
        free(retType); // Free the allocated memory
        YYERROR;
    }
            if (!insertSymbolEntrycheckdefine($2->token, retType)) {
        free(retType); // Free the allocated memory
        YYERROR;
    }
    
    
	$$ = mknode("FUNC", mknode( NULL, mknode( NULL, mknode( $2->token, NULL, NULL), mknode( "ARGS", $4, NULL)), mknode( NULL, mknode( retType, NULL, NULL), mknode("BODY", $9, NULL))), mknode(NULL, NULL, NULL));
	
}

/* Args */
ARGS:                                              {$$ = NULL;}
    | ARGS_SECTION                                 {$$ = mknode(NULL, $1, NULL);};

ARGS_SECTION: ARG ARG_INPUTS ':' TYPE              {$$ = mknode($4->token, $2, NULL);}    
            | ARGS ';' ARG ARG_INPUTS ':' TYPE     {$$ = mknode(NULL, $1, mknode($6->token, $4, NULL));};

ARG_INPUTS: INPUT ',' INPUT                        {$$ = mknode( NULL, $1, $3); }   
	      | INPUT                                  {$$ = $1;};


/* Body */
BODY: FUNCS STMTS        {$$ = mknode(NULL, $1, $2);}
    | STMTS              {$$ = mknode(NULL, $1, NULL);};


/* Statments */
STMTS:               {$$ = NULL;}
     | STMT STMTS    {$$ = mknode(NULL, $1, $2);};

STMT: VAR_ ';'            {$$ = mknode(NULL, $1, NULL);}
    | IF_ST               {$$ = mknode(NULL, $1, NULL);}
	| LOOP                {$$ = mknode(NULL, $1, NULL);}
    | RETURN_STMT ';'     {$$ = mknode(NULL, $1, NULL);}
    | '{' STMTS '}'       {$$ = mknode(NULL, mknode("{", $2, NULL), mknode("}", NULL, NULL));};


RETURN_STMT: RETURN VAR_ASSIGN  {$$ = mknode("RETURN", $2, NULL);}
           | RETURN INPUT       {$$ = mknode("RETURN", $2, NULL);};


/* Variable */
VAR_: VAR_ASSIGN  VAR_NEST       {$$ = mknode(NULL, $1, $2);}
    | VAR_DEC     VAR_NEST       {$$ = mknode(NULL, $1, $2);}
    | ARR_VAR     VAR_NEST       {$$ = mknode(NULL, $1, $2);}
    | ARR_ASSIGN  VAR_NEST       {$$ = mknode(NULL, $1, $2);}
    | FUNC_                      {$$ = mknode(NULL, $1, NULL);};   

FUNC_: ID '(' LENGTH ')'      {$$ = mknode($1, NULL, $3);}
  
VAR_NEST: ',' VAR_               {$$ = mknode(",", $2, NULL);}
        |                        {$$ = NULL;};
        
VAR_DEC: VAR_LHS ':' TYPE        {$$ = mknode(":", $1, $3);};

VAR_ASSIGN: VAR_LHS '=' RHS      {$$ = mknode("=", $1, $3);};

VAR_LHS: INPUT                   {$$ = mknode( NULL, $1, NULL);}
       | VAR INPUT               {$$ = mknode( "VAR", $2, NULL);}
       | VAR INPUT '=' EXP       {$$ = mknode( "VAR", mknode( "=", $2, $4), NULL);}
       | '*' INPUT               {$$ = mknode( "*", $2, NULL);};//CHECK

RHS: ID ':' TYPE                 {$$ = mknode(":", mknode($1, NULL, NULL), $3);} // Changed
   | EXP                         {$$ = $1;}
   | INPUT EXP                   {$$ = mknode( NULL, $1, $2);};
   | POINTER                     {$$ = mknode(NULL, $1, NULL);}

EXP: INPUT                       {$$ = $1;}
   | EXP '+' EXP                 {$$ = mknode( "+", $1, $3);}
   | EXP '-' EXP                 {$$ = mknode( "-", $1, $3);}
   | EXP '*' EXP                 {$$ = mknode( "*", $1, $3);}
   | EXP '/' EXP                 {$$ = mknode( "/", $1, $3);}
   | EXP '+''+'                  {$$ = mknode( "++", $1, NULL);}
   | EXP '-''-'                  {$$ = mknode( "--", $1, NULL);}
   | '(' EXP ')'                 {$$ = mknode(NULL,mknode("(", $2, NULL), mknode(")", NULL, NULL));}
   | '(' LENGTH ')'              {$$ = mknode(NULL,mknode("(", $2, NULL), mknode(")", NULL, NULL));}


POINTER: '&' ID                  {$$ = mknode( NULL, mknode("&", NULL, NULL), mknode($2, NULL, NULL));}
       | '&' ID '[' EXP ']'      {$$ = mknode( "&", mknode($2, mknode("[", $4, NULL), mknode("]", NULL, NULL)), NULL);}
       | '*' '(' EXP ')'         {$$ = mknode( "*", mknode("(", $3, NULL), mknode(")", NULL, NULL));};


/* Array */
ARR_VAR: ID '(' ARG_INPUTS ')'  {$$ = mknode( $1, mknode("(", $3, NULL), mknode(")", NULL, NULL));} 
       | STRING ID '[' EXP ']'  {$$ = mknode( "STRING", mknode($2, mknode("[", $4, NULL), mknode("]", NULL, NULL)), NULL);};

ARR_ASSIGN: ARR_LHS '=' RHS     {$$ = mknode("=", $1, $3);};

ARR_LHS: ID '[' EXP ']'         {$$ = mknode( $1, mknode("[", $3, NULL), mknode("]", NULL, NULL));} 
       | STRING ID '[' EXP ']'  {$$ = mknode( "STRING", mknode($2, mknode("[", $4, NULL), mknode("]", NULL, NULL)), NULL);};


//IF and ELSE
IF_ST: IF '(' COND ')' BLOCK_OP ELSE_  {$$ = mknode("IF", mknode(NULL, $3, $5), $6);}

ELSE_: ELSE BLOCK_OP                   {$$ = mknode(NULL, $2, NULL);}
	 |                                 {$$ = NULL;};


//LOOP
LOOP: FOR '(' VAR_ ';' COND ';' VAR_ ')' BLOCK_OP     {$$ = mknode("FOR", mknode(NULL, $3, $5), mknode(NULL, $9 ,$7));}
    | WHILE '(' COND ')' BLOCK_OP                     {$$ = mknode("WHILE", $3, $5);} 
    | DO BLOCK_OP WHILE '(' COND ')' ';'              {$$ = mknode("DO", $2, mknode("WHILE", $5, NULL));}; 



//Utilites

BLOCK_OP: '{' BODY '}'   {$$ = mknode("BLOCK", $2, NULL);}
        | STMT           {$$ = mknode("BLOCK", $1, NULL);};     


TYPE: BOOL        { $$ = mknode(strdup(yytext), NULL, NULL);}
    | CHAR        { $$ = mknode(strdup(yytext), NULL, NULL);}
    | INT         { $$ = mknode(strdup(yytext), NULL, NULL);}
    | REAL        { $$ = mknode(strdup(yytext), NULL, NULL);}
    | STRING      { $$ = mknode(strdup(yytext), NULL, NULL);}
    | INTPTR      { $$ = mknode(strdup(yytext), NULL, NULL);}
    | CHARPTR     { $$ = mknode(strdup(yytext), NULL, NULL);} 
    | REALPTR     { $$ = mknode(strdup(yytext), NULL, NULL);}; 


INPUT: INTVAL     {$$ = mknode( $1, NULL, NULL);}
     | REALVAL    {$$ = mknode( $1, NULL, NULL);}
     | CHARVAL    {$$ = mknode( $1, NULL, NULL);}
     | STRINGVAL  {$$ = mknode( $1, NULL, NULL);}
     | TRUE       {$$ = mknode( $1, NULL, NULL);}
     | FALSE      {$$ = mknode( $1, NULL, NULL);}
     | ID         {$$ = mknode( $1, NULL, NULL);} 
     | NULLL      {$$ = mknode( $1, NULL, NULL);}
     | NUMVAL     {$$ = mknode( $1, NULL, NULL);};


COND: COND '<' COND         {$$ = mknode( "<", $1, $3);}
    | COND '>' COND		    {$$ = mknode( ">", $1, $3);}
    | COND BIGGEREQL COND   {$$ = mknode( ">=", $1, $3);}
    | COND SMALLEREQL COND  {$$ = mknode( "=<", $1, $3);}
    | COND OR COND          {$$ = mknode( "||", $1, $3);}
    | COND EQL COND		    {$$ = mknode( "==", $1, $3);}
    | COND AND COND		    {$$ = mknode( "&&", $1, $3);}
    | COND NOTEQL COND	    {$$ = mknode( "!=", $1, $3);}
    | '!' '(' COND ')'      {$$ = mknode("!", mknode("(", $3, NULL), mknode(")", NULL, NULL));}
	| INPUT			        {$$ = $1;}
    | ARR_LHS               {$$ = $1;};

LENGTH: '|' INPUT '|'      {$$ = mknode( NULL, mknode(NULL, mknode("|", $2, NULL), mknode("|", NULL, NULL)), NULL);}

%%

void main(){
    yyparse();
    if(!yydebug){
        printf("WORK!!!\n");
    }
}

void yyerror(const char *s) {
  yydebug = 1;
  fflush(stdout);
  fprintf(stderr, "Error: %s at line %d\n", s, yylineno);
  fprintf(stderr, "does not accept '%s'\n", yytext);
}

int yywrap() {
    return 1;
}

/* AST */
struct node *mknode(char *token, node *left, node *right) { 
    node *newnode = (node*)malloc(sizeof(node)); 

    if(token != NULL) {
        char *newstr = (char*)malloc(strlen(token) + 1); 
        strcpy(newstr, token); 
        newnode->token = newstr; 
    }
    else {
        newnode->token = strdup("");  // use an empty string for NULL tokens
    }

    newnode->left = left; 
    newnode->right = right; 

    return newnode; 
}


int printtree(node* tree) {
    if(tree == NULL) {
        return 0;
    }

    Count1++;

    // check if the node has a token and at least one child
    if (tree->token != NULL && strlen(tree->token) > 0 && (tree->left || tree->right)) {
        printTab();
        printf("(%s\n", tree->token);
    } else if (tree->token != NULL && strlen(tree->token) > 0) {
        printTab();
        printf("%s\n", tree->token);
    }

    Count2 = Count1;

    if(tree->left) printtree(tree->left);
    if(tree->right) printtree(tree->right);

    // check if the node has a token and at least one child
    if (tree->token != NULL && strlen(tree->token) > 0 && (tree->left || tree->right)) {
        printTabs();
        printf(")\n");
    }
    Count2--;
    Count1--;

    return 1;
}



void printTab() {
	for(int i=0;i<Count1;i++){
		printf(" ");	
	}
}

void printTabs(){
	int i;
	for(i=0;i<Count2;i++){
		printf(" ");	
	}
}

void freeAST(node* tree) {
	freeNode(tree);
}

void freeNode(node* node) {
	if (node == NULL)
		return;

	free(node->token);
	freeNode(node->left);
	freeNode(node->right);
	free(node);
}

bool insertSymbolEntry(char* name, char* type) {
    // Check if the symbol already exists
    for (size_t i = 0; i < symbolCount; i++) {
        if (strcmp(symbolTable[i].name, name) == 0) {
            printf("Error: Duplicate symbol '%s'\n", name);
            return false;
        }
    }

    // Insert the symbol into the symbol table
    SymbolEntry entry;
    entry.name = strdup(name);
    entry.type = strdup(type);
    symbolTable[symbolCount++] = entry;
    
    return true;
}

int insertSymbolEntrycheck(char *name, char *type) {
    // Check for duplicate function names
    SymbolEntry *entry = symbolTable;
    while (entry != NULL) {
        if (strcmp(entry->name, name) == 0) {
            printf("Error: Duplicate function name '%s'\n", name);
            return 0;
        }
        entry = entry->next;
    }

    // Check for duplicate variable names
    entry = symbolTable;
    while (entry != NULL) {
        if (strcmp(entry->name, name) == 0) {
            printf("Error: Duplicate variable name '%s'\n", name);
            return 0;
        }
        entry = entry->next;
    }

    // Create a new symbol entry
     //SymbolEntry *newEntry = (SymbolEntry *)malloc(sizeof(SymbolEntry));
     //newEntry->name = strdup(name);
     //newEntry->type = strdup(type);
     //newEntry->next = symbolTable;
     //symbolTable = newEntry;
    SymbolEntry *newEntry = &symbolTable[symbolTableIndex];
    newEntry->name = strdup(name);
    newEntry->type = strdup(type);
    newEntry->next = NULL;

    symbolTableIndex++;
    return 1;
}

bool insertSymbolEntrycheckdefine(char* name, char* type) {
    // Check if the symbol already exists in the symbol table
    for (int i = 0; i < symbolTableIndexcheck; i++) {
        if (strcmp(symbolTable[i].name, name) == 0) {
            // Symbol already exists, return false (failure)
            return false;
        }
    }

    // Create a new symbol entry
    SymbolEntry newEntry;
    newEntry.name = strdup(name);
    newEntry.type = strdup(type);
    newEntry.isDefined = false;       // For functions
    newEntry.isInitialized = false;   // For variables

    // Insert the new symbol entry into the symbol table
    symbolTable[symbolTableIndexcheck++] = newEntry;

    // Return true (success)
    return true;
}
