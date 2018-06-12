#include <stdio.h>
#include <string.h>   //strlen
#include <stdlib.h>
#include <getopt.h>
#include <ctype.h>
#include "logging.h"
#include "proxy_state.h"
#include <string.h>
#include <sys/types.h>   // socket
#include <sys/socket.h>  // socket
#include <netinet/in.h>
/**
 * El estado global del proxy en cualquier momento, deberia poderse acceder 
 * desde cualquier parte del proxy
 */
global_proxy_state *proxy_state;

int parse_cli_options(int argc, char **argv);

bool
proxy_state_create(int argc, char **argv) {

	proxy_state = malloc(sizeof(*proxy_state));

	// Set Defaults
	proxy_state->bytesTransfered = 0;
	proxy_state->port = 1080;
  proxy_state->buffer = 5000;
	proxy_state->confPort = 1081;
	proxy_state->do_transform = false;
	proxy_state->transformation_command_index=0;

  /** request count */
  proxy_state->request_count = 0;

  /** byte count */
  proxy_state->byte_count = 0;

  /** total current connections */
  proxy_state->live_connections = 0;
	
	char default_command[] = "sed -u -e 's/a/4/g' -e 's/e/3/g' -e 's/i/1/g' -e 's/o/0/g' -e's/s/5/g'";
	proxy_state->transformation_command = calloc(strlen(default_command) , sizeof(char));
	strcpy(proxy_state->transformation_command, default_command);

	char default_stderr[] = "/dev/null";
	proxy_state->filters_stderr = calloc(strlen(default_stderr) , sizeof(char));
	strcpy(proxy_state->filters_stderr, default_stderr);
	
	

	proxy_state->proxy_interface = INADDR_LOOPBACK;
	proxy_state->http_interface = INADDR_ANY;

  proxy_state->transformation_types_index = 0;
	proxy_state->transformation_types = calloc(1 , sizeof(char));

    int ret = parse_cli_options(argc, argv);
    if (ret < 0) {
    	LOG_ERROR("Failed to initialize proxy conf. ABORTING!", "ip", "request");
    	proxy_state_destroy();
    }
	return true;
}

void
proxy_state_destroy() {
	free(proxy_state->transformation_command);
	free(proxy_state->transformation_types);
	free(proxy_state->filters_stderr);
	//free(proxy_state->proxy_interface);
	//free(proxy_state->http_interface);
    free(proxy_state);
}

int parse_cli_options(int argc, char **argv) {

    int c;
    char *aux;
    while ((c = getopt (argc, argv, "e:hl:L:M:o:p:t:v:T")) != -1)
        switch (c) {
          case 'h': //help
          	  LOG_DEBUG("Manpage request by CLI");
              system("man ./httpd.8");
              exit(1);
              break;
          case 'v': //version
          	  LOG_DEBUG("Version request by CLI");
              puts("ADMIN_V1");
              exit(0);
              break;
          case 'e': //error file
          	  proxy_state->filters_stderr = realloc(proxy_state->filters_stderr, strlen(optarg)*sizeof(char));
              strcpy(proxy_state->filters_stderr, optarg);
              proxy_state->filters_stderr[strlen(optarg)] = '\0';
              break;
          case 'l': //proxy listening interface,, default al
          	   if (strcmp(optarg,"localhost") == 0){
                 proxy_state->http_interface = INADDR_LOOPBACK;
               }
              break;
          case 'p': //proxy port TODO
              proxy_state->port = atoi(optarg);	
              break;
          case 'L': //mng listening interface, default loopback
          	   if (strcmp(optarg,"any") == 0)
                 proxy_state->proxy_interface = INADDR_ANY;
              break;
          case 'o': //mng port TODO
          	  proxy_state->confPort = atoi(optarg);	
              break;
          case 'M': //media types to filter
              proxy_state->transformation_types = realloc(proxy_state->transformation_types, strlen(optarg)*sizeof(char));
              strcpy(proxy_state->transformation_types, optarg);
              proxy_state->transformation_types[strlen(optarg)] = '\0';
              break;
          case 't': //cmd
              proxy_state->transformation_command = realloc(proxy_state->transformation_command, strlen(optarg)*sizeof(char));
              strcpy(proxy_state->transformation_command, optarg);
              proxy_state->transformation_command[strlen(optarg)] = '\0';
              break;
          case 'T': //cmd
              proxy_state->do_transform = true;
              break;
          case '?': //TODO emprolijar los casos de erro de aca
              if (optopt == 'e' || optopt == 'l' || optopt == 'p' || optopt == 'L'
                      || optopt == 'o' || optopt == 'P' || optopt == 'm' || optopt == 'M'
                      || optopt == 't' )
                  fprintf (stderr, "Option -%c requires an argument.\n", optopt);
              else if (isprint (optopt))
                  fprintf (stderr, "Unknown option `-%c'.\n", optopt);
              else
                  fprintf (stderr,
                           "Unknown option character `\\x%x'.\n",
                           optopt);
              return false;
        }


    char str[1000];
    snprintf(str, 1000, "Starting new instance of proxy HTTP:\n \
      \terror_file = %s\n \
      \thttp_interface = %s\n \
      \tproxy_port = %d\n \
      \tproxy_interface = %s\n \
      \tproxy_mng_port = %d\n \
      \tdo_transform = %s\n \
      \ttransformation_types = %s\n \
      \tbuffer= %d\n \
      \ttransformation_command = %s",
             (proxy_state->filters_stderr),
             (proxy_state->http_interface == INADDR_ANY)? "INADDR_ANY":"LOOPBACK",
             (proxy_state->port),
             (proxy_state->proxy_interface == INADDR_ANY)? "INADDR_ANY":"LOOPBACK",
             (proxy_state->confPort),
             proxy_state->do_transform?"ON":"OFF",
             (proxy_state->transformation_types),
             proxy_state->buffer,
             (proxy_state->transformation_command));
    LOG_PRIORITY(str);
    return true;
}