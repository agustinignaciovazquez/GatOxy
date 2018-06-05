/**
 * main.c - servidor proxy socks concurrente
 *
 * Interpreta los argumentos de línea de comandos, y monta un socket
 * pasivo.
 *
 * Todas las conexiones entrantes se manejarán en éste hilo.
 *
 * Se descargará en otro hilos las operaciones bloqueantes (resolución de
 * DNS utilizando getaddrinfo), pero toda esa complejidad está oculta en
 * el selector.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <signal.h>

#include <unistd.h>
#include <sys/types.h>   // socket
#include <sys/socket.h>  // socket
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/sctp.h>
#include "selector.h"
#include "httpproxynio.h"
#include "sctpadminnio.h"
#include "logging.h"

static bool done = false;

static void
sigterm_handler(const int signal) {
    printf("signal %d, cleaning up and exiting\n",signal);
    done = true;
}

int
main(const int argc, const char **argv) {
    unsigned port = 1080;
    unsigned confPort = 1090;

    if(argc == 1) {
        // utilizamos el default
    } else if(argc == 2) {
        char *end     = 0;
        const long sl = strtol(argv[1], &end, 10);

        if (end == argv[1]|| '\0' != *end 
           || ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == errno)
           || sl < 0 || sl > USHRT_MAX) {
            fprintf(stderr, "port should be an integer: %s\n", argv[1]);
            return 1;
        }
        port = sl;
    } else {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        return 1;
    }

    // no tenemos nada que leer de stdin
    close(0);

    const char       *err_msg = NULL;
    selector_status   ss      = SELECTOR_SUCCESS;
    fd_selector selector      = NULL;

    //conf HTTP server
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port        = htons(port);

    const int server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(server < 0) {
        err_msg = "unable to create http socket";
        goto finally;
    }

    // man 7 ip. no importa reportar nada si falla.
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));

    if(bind(server, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
        err_msg = "unable to bind http socket";
        goto finally;
    }

    if (listen(server, 20) < 0) {
        err_msg = "unable to listen http";
        goto finally;
    }

    fprintf(stdout, "Listening on TCP port %d\n", port);

    //conf SCTP conf server
    struct sockaddr_in confAddr;
    memset(&addr, 0, sizeof(confAddr));
    confAddr.sin_family      = AF_INET;
    confAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    confAddr.sin_port        = htons(confPort);

    const int confServer = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
    if(confServer < 0) {
        err_msg = "unable to create sctp socket";
        goto finally;
    }

    if(bind(confServer, (struct sockaddr*) &confAddr, sizeof(confAddr)) < 0) {
        err_msg = "unable to bind sctp socket";
        goto finally;
    }

    // man 7 ip. no importa reportar nada si falla.
    struct sctp_initmsg initmsg;
    /* Specify that a maximum of 5 streams will be available per socket */
    memset( &initmsg, 0, sizeof(initmsg) );
    initmsg.sinit_num_ostreams = 5;
    initmsg.sinit_max_instreams = 5;  // TODO hay que limpiar esto, lo ensucie tratando de ver sctp en netstat,,(resulta no soporta sctp)
    initmsg.sinit_max_attempts = 4;
    int aux = setsockopt( confServer, IPPROTO_SCTP, SCTP_INITMSG, &initmsg, sizeof(initmsg) );
    if (aux < 0) LOG_DEBUG("main.c error de stsockpt");

    if (listen(confServer, 20) < 0) {
        err_msg = "unable to listen sctp";
        goto finally;
    }

    
    fprintf(stdout, "Listening on SCTP port %d\n", confPort);

    // registrar sigterm es útil para terminar el programa normalmente.
    // esto ayuda mucho en herramientas como valgrind.
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT,  sigterm_handler);

    if(selector_fd_set_nio(server) == -1) {
        err_msg = "getting http server socket flags";
        goto finally;
    }

    if(selector_fd_set_nio(confServer) == -1) {
        err_msg = "getting sctp server socket flags";
        goto finally;
    }

    const struct selector_init conf = {
        .signal = SIGALRM,
        .select_timeout = {
            .tv_sec  = 10,
            .tv_nsec = 0,
        },
    };

    if(0 != selector_init(&conf)) {
        err_msg = "initializing selector";
        goto finally;
    }

    selector = selector_new(1024);
    if(selector == NULL) {
        err_msg = "unable to create selector";
        goto finally;
    }
    
    // register master http socket
    const struct fd_handler socksv5 = {
        .handle_read       = socksv5_passive_accept,
        .handle_write      = NULL,
        .handle_close      = NULL, // nada que liberar
    };
    ss = selector_register(selector, server, &socksv5,
                                              OP_READ, NULL);
    if(ss != SELECTOR_SUCCESS) {
        err_msg = "registering socksv5 fd";
        goto finally;
    }

    // register master sctp socket TODO
    const struct fd_handler sctp = {
        .handle_read       = sctp_passive_accept,
        .handle_write      = NULL,
        .handle_close      = NULL, // nada que liberar
    };
    ss = selector_register(selector, confServer, &sctp,
                                              OP_READ, NULL);
    if(ss != SELECTOR_SUCCESS) {
        err_msg = "registering sctp fd";
        goto finally;
    }

    // start ininite proxy loop
    for(;!done;) {
        LOG_DEBUG("main.c ::: iteration");
        err_msg = NULL;
        ss = selector_select(selector);
        if(ss != SELECTOR_SUCCESS) {
            err_msg = "serving";
            goto finally;
        }
    }
    if(err_msg == NULL) {
        err_msg = "closing";
    }

    int ret = 0;
finally:
    if(ss != SELECTOR_SUCCESS) {
        fprintf(stderr, "%s: %s\n", (err_msg == NULL) ? "": err_msg,
                                  ss == SELECTOR_IO
                                      ? strerror(errno)
                                      : selector_error(ss));
        ret = 2;
    } else if(err_msg) {
        perror(err_msg);
        ret = 1;
    }
    if(selector != NULL) {
        selector_destroy(selector);
    }
    selector_close();

    socksv5_pool_destroy();
    sctp_pool_destroy();

    if(server >= 0) {
        close(server);
    }
    return ret;
}
