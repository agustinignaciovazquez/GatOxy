#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int main(int argc, char *argv[]) {

  puts("Hello World!");

  // parsear todos los parametros de entrada a una estructura
  // general que tenga ya los defaults. Que esta estructura este disponible para toda la app.


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