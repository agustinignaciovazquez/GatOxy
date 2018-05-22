#include <stdio.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

extern struct proxy_conf *proxy_conf;


char* get_time(){
  time_t rawtime;
  struct tm * timeinfo;
  time ( &rawtime );
  timeinfo = localtime ( &rawtime );
  return asctime (timeinfo);
}

int write_to_file(char *str) {
  FILE *file;
  file = fopen("temp_log.log\0", "a"); // TODO que implemente el archivo desde el proxy conf
   if(file == NULL){
      printf("\n\n***  Error writing log  ***\n\n");
      return 0;
   }
   fprintf(file,"%s\n", str);
   fclose(file);
   return 1;
}

void LOG_DEBUG(char *str) {
  char aux[1000];
  strcpy(aux,get_time());
  aux[strlen(aux)-1] = '\0';
  strcat(aux, ":::: ");
  strcat(aux, str);
  write_to_file(aux);
}

void LOG_PRIORITY(char *str) {
  write_to_file("*******************************************");
  write_to_file(get_time());
  write_to_file(str);
  write_to_file("*******************************************");
}
