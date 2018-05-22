struct proxy_conf {
  char log_file[25];
  char proxy_port[10]; //option p
  char proxy_mng_port[10]; //option o  GET
  int master_socket;
  int conf_socket;

  //para metricas
  int total_transfered_bytes;
};
struct proxy_conf* proxy_conf;
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include "logging.h"

#define TRUE   1
#define FALSE  0




struct proxy_conf* parse_cli_options(int argc, char *argv[]);

int main(int argc, char *argv[]) {

  LOG_PRIORITY("STARTING NEW INSTANCE OF PROXY SERVER");
  puts("Hello World!");

  // parsear todos los parametros de entrada a una estructura
  // general que tenga ya los defaults. Que esta estructura este disponible para toda la app.
  proxy_conf = parse_cli_options(argc, argv);


  // inicializar una linked list referenciada por el struct de configuracion
  // cada nodo de esta lista representa cada linea de comunicacion.
  // tendra dos sockets asociados. El que va al cliente y el que va al servidor destino
  // ademas tendra un buffer circular de cada cosa pendiente por escribir a cada socket
  // por ultimo, cada socket tendra un estado asociado a un automata, cada vez que el socket se activa
  // ejecutaremos su estado que automaticamente lo dejara en el estado que sigue


  // bindeamos al puerto para escuchar clientes nuevos  HTTP proxy --> socket pasivo http
  // bindeamos al puerto para escuchar admins nuevos SCTP admin ---> socket pasivo admin

  // hacemos un while true que pone en un select los sockets http, admin y todos los de la linked list.
  // cuando el select se dispara, se itera por todos los sockets viendo cual lo desperto, para dicho socket
  // se ejecuta la funcion correspondiente al estado de ese socket
  // luego se carga el select nuevamente .
  //     cuando el disparo fue por una conexion entrante, se crea un nodo nuevo en la lista y se lo carga con los estados
  //        iniciales.
  //     cuando el disparo fue por una conexion entrante, es pq uno de los sockets esta ready para ser escrito o para ser
  //        leido, se ejecuta el estado correspondiente que leera o escribira, cambiara el estado y terminara.


}

/**
*Name: new_proxy_conf
*
*Description: Create Poxy conf struct with defaults
*
*@return proxy_conf
**/
struct proxy_conf* new_proxy_conf(){
  LOG_DEBUG("Creating proxy conf struct.");
  struct proxy_conf* proxy_conf = malloc(sizeof(struct proxy_conf));
  memcpy(proxy_conf->log_file, "debug.log\0", strlen("debug.log\0"));
  memcpy(proxy_conf->proxy_mng_port, "1110\0", strlen("1110\0"));
  memcpy(proxy_conf->proxy_port, "9090\0", strlen("9090\0"));
  proxy_conf->total_transfered_bytes = 0;
  LOG_DEBUG("Succesfuly created proxy conf struct.");
  return proxy_conf;
}

/**
*Name: parse_cli_options
*
*Description: Parse CLI arguments and return general proxy confs
*
*
*@param int argc
*@param char *argv[]
*@return proxy_conf
**/
struct proxy_conf* parse_cli_options(int argc, char *argv[]) {

    struct proxy_conf* proxy_conf = new_proxy_conf();

    int c;
    char *aux;

    // TODO this switch is not working, using defaults mean while
    LOG_DEBUG("Starting parse of cli arguments.");
//    while ((c = getopt (argc, argv, "p:P")) != -1)
//        switch (c) {
//            case 'P': //proxy_port
//                memcpy(proxy_conf->proxy_port, optarg, strlen(optarg));
//                break;
//            case 'p': //proxy_mng_port
//                memcpy(proxy_conf->proxy_mng_port, optarg, strlen(optarg));
//                break;
//            case '?':
//                if (optopt == 'p' || optopt == 'P')
//                    fprintf (stderr, "Option -%c requires an argument.\n", optopt);
//                else if (isprint (optopt))
//                    fprintf (stderr, "Unknown option `-%c'.\n", optopt);
//                else
//                    fprintf (stderr,
//                             "Unknown option character `\\x%x'.\n",optopt);
//                LOG_PRIORITY("Failed to parse cli arguments. Aborting execution.");
//                exit(1);
//        }
    LOG_DEBUG("Succesfuly parsed cli arguments.");
    return proxy_conf;
}