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
	bool previous_was_space = true;
	int regex_size = strlen(regex);
	int str_size = strlen(str);
	if (strlen(regex) == 0) return true; // TODO si no tengo regex, matcheo todo????

	int str_index = 0;

	int i;
	for (i = 0;i<regex_size && str_index<str_size ;){
		
		printf("1- >%c<>%c< \n",regex[i],  str[str_index]);

		//skip all space characters
		if (regex[i] == ' ') {
			i++;
			continue;
		}
		if (str[str_index] == ' ') {
			str_index++;
			continue;
		}
		
		//if currently on regex = *
		if ( regex[i] == '*' ) {
			printf("2- >%c<>%c< \n",regex[i],  str[str_index]);
			
			// check if char not \0
			if ( str[str_index] != ';' && str[str_index] != '\0'  ) {
				printf("3- >%c<>%c< \n",regex[i],  str[str_index]);
					str_index++;
					continue;
			}
			i++;
			continue;
		}

		//compare char to char
		if (tolower(regex[i]) != tolower(str[str_index])){
			return false; // default case, chars should match	
		} 
		str_index++;
		i++;
	}

	if ( regex[i] == '*' ) i++;

	// valido que los dos el siguiente sea \0
	printf("4-%d>%c<%d>%c< \n",i,regex[i], str_index, str[str_index]);
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
	assert(regexParser("text/html", " text/hTml"));
	assert(!regexParser("text/html ; iso-algo", "text/hTml ; is-algo"));
	assert(!regexParser("text/* ; iso-algo", "text/hTml ; is-algo"));
	assert(regexParser("text/* ; iso-algo", "text/hTml ; iso-algo"));
	assert(regexParser("text/* ; charset=*", "text/hTml ; charset=utf-8"));
	assert(regexParser("text/* ; charset=*", "text/ hTml ; charset=utf-8"));
	assert(!regexParser("text/plain", "text/plain; charset=utf-8"));
	assert(regexParser("*", "dsfsdf"));
	
}