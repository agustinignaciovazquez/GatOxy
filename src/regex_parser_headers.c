/**
 * admin.c -- parser del admin de SOCKS5 que recive la llamada
 * TODO emprolijar
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>
#include <ctype.h>
#include <string.h>


bool regexParser(char *regex, char *str) {
	int regex_size = strlen(regex);
	int str_size = strlen(str);
	if (strlen(regex) == 0) return true; // TODO si no tengo regex, matcheo todo????

	int regex_index = 0;
	int str_index = 0;

	int i;
	for (i = 0; i < regex_size; ++i){
		if (tolower(regex[i]) == '*') return true; // wildcard
		// if (tolower(str[i]) == ' ') return false; // invalid string str
		// if (tolower(regex[i]) == ' ') return false; // invalid string regex
		if (tolower(regex[i]) != tolower(str[i])) return false; // default case, chars should match
		str_index++;
	}

	// valido que los dos el siguiente sea \0
	if (tolower(regex[i]) != tolower(str[str_index])) return false;

	return true;
}

int main(int argc, char const *argv[]) {
	
	assert(!regexParser("media/type", ""));
	assert(!regexParser("media/type", "media/tY"));
	assert(regexParser("media/*", "media/tY"));
	assert(regexParser("text/html", "text/html"));
	assert(regexParser("text/html", "text/hTml"));
	assert(!regexParser("text/html", "text/hTml "));
	assert(!regexParser("text/html", " text/hTml"));
	assert(!regexParser("text/html ; iso-algo", "text/hTml ; is-algo"));
	assert(regexParser("*", "dsfsdf"));
	
}