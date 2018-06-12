#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>   // socket
#include <sys/socket.h>  // socket
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <arpa/inet.h>


#define MAX_BUFFER	1024
#define LOCALTIME_STREAM	0
#define GMT_STREAM		1




typedef struct arguments {
	char *ip;
	unsigned port;
	char *payload;
} args;

void build_command(int argc, char **argv, args *args );

int main(int argc, char **argv) {
	args *args= malloc(sizeof(args));

	//parse cli
	build_command(argc,argv, args);
puts("END build command");
  int connSock, in, i, ret, flags;
  struct sockaddr_in servaddr;
  struct sctp_status status;
  struct sctp_sndrcvinfo sndrcvinfo;
  struct sctp_event_subscribe events;
  struct sctp_initmsg initmsg;
  char buffer[MAX_BUFFER+1];

  /* Create an SCTP TCP-Style Socket */
  connSock = socket( AF_INET, SOCK_STREAM, IPPROTO_SCTP );
puts("creat socket");
  /* Specify that a maximum of 5 streams will be available per socket */
  memset( &initmsg, 0, sizeof(initmsg) );
  initmsg.sinit_num_ostreams = 5;
  initmsg.sinit_max_instreams = 5;
  initmsg.sinit_max_attempts = 4;
  ret = setsockopt( connSock, IPPROTO_SCTP, SCTP_INITMSG,
                     &initmsg, sizeof(initmsg) );
puts("post setsockopt");
  /* Specify the peer endpoint to which we'll connect */
  bzero( (void *)&servaddr, sizeof(servaddr) );
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(args->port);
puts("post htons");
  servaddr.sin_addr.s_addr = inet_addr( args->ip );
puts("post servaddr create");
  /* Connect to the server */
puts("pre connect");
  ret = connect( connSock, (struct sockaddr *)&servaddr, sizeof(servaddr) );
puts("post connect");

  /* Enable receipt of SCTP Snd/Rcv Data via sctp_recvmsg */
  memset( (void *)&events, 0, sizeof(events) );
  events.sctp_data_io_event = 1;
  ret = setsockopt( connSock, SOL_SCTP, SCTP_EVENTS,
                     (const void *)&events, sizeof(events) );

  /* Read and emit the status of the Socket (optional step) */
  in = sizeof(status);
  ret = getsockopt( connSock, SOL_SCTP, SCTP_STATUS,
                     (void *)&status, (socklen_t *)&in );

  printf("assoc id  = %d\n", status.sstat_assoc_id );
  printf("state     = %d\n", status.sstat_state );
  printf("instrms   = %d\n", status.sstat_instrms );
  printf("outstrms  = %d\n", status.sstat_outstrms );

  /* Expect two messages from the peer */
puts("pre print");

  //Send some data
puts(args->payload);
	ret = send(connSock , args->payload , strlen(args->payload) , 0);
	if( ret < 0) {
		puts("Send failed");
		close(connSock);
		return -1;
	}

	//Receive a reply from the server
	char server_reply[2000];
	recv(connSock , server_reply , 2000 , 0);
    if( recv(connSock , server_reply , 2000 , 0) < 0) {
        puts("recv failed");
        close(connSock);
        return -1;
    }
         
    puts("Server reply :");
    puts(server_reply);


  /* Close our socket and exit */
  close(connSock);

  return 0;	

}


void build_command(int argc, char **argv, args *args ){
  char* buffer = malloc( sizeof(char) * 1024 );
  int c;
  while ((c = getopt (argc, argv, "a:p:c:")) != -1){
          switch (c) {
          case 'a': //ip
          puts("ip");
                  args->ip = calloc(strlen(optarg),sizeof(char));
                  strcpy(args->ip, optarg);
                  break;

          case 'p'://port
          puts("port");
                  args->port = atoi(optarg);
                  break;
          case 'c': //command
                  args->payload = calloc(strlen(optarg)+2,sizeof(char));
                  strcpy(args->payload, optarg);
                  strcat(args->payload, "\r\n");
                  break;
          default:
                  break;
          }
  }
}