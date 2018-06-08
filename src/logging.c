#include <stdio.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include "logging.h"

char* get_time(){
  time_t rawtime;
  struct tm * timeinfo;
  time ( &rawtime );
  timeinfo = localtime ( &rawtime );
  return asctime (timeinfo);
}

int write_to_file(char *str, char *path) {
  FILE *file;
  file = fopen(path, "a");
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
  strcat(aux, ":: DEBUG ::");
  strcat(aux, str);
  write_to_file(aux, DEV_LOG);
}

void LOG_ERROR(char *str) {
  if(DEV_ENABLED == 0) return;
  char aux[1000];
  strcpy(aux,get_time());
  aux[strlen(aux)-1] = '\0';
  strcat(aux, ":: ERROR :: ");
  strcat(aux, str);
  write_to_file(aux, DEV_LOG);
  write_to_file(aux, PROD_LOG);
}

void LOG_PRIORITY(char *str) {
  char aux[1000] = "*******************************************\n";
  strcat(aux, get_time());
  strcat(aux, str);
  strcat(aux, "\n");
  strcat(aux, "*******************************************");
  write_to_file(aux, DEV_LOG);
  write_to_file(aux, PROD_LOG);
}

unsigned LOG_RECOVER(char *str, int bytes, char *path) {
  FILE *fp;
  fp = fopen(path, "r");
  if(fp == NULL){
      return snprintf(str, bytes," LOGS UNAVAILABLE\n");
   }
  fseek(fp, 0L, SEEK_END);
  int sz = ftell(fp);
  int back = sz - bytes;
  if (back < 0) back = 0;
  fseek(fp, back , SEEK_SET);
  unsigned n = fread(str, sizeof(char), bytes, fp);
  fclose(fp);
  return n;
}







