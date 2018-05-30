#include<stdio.h>
#include <stdlib.h>  // malloc
#include <string.h>  // memset
#include <assert.h>  // assert
#include <errno.h>
#include <time.h>
#include <unistd.h>  // close
#include <pthread.h>

#include <arpa/inet.h>

#include "HTTPRequest.h"
#include "buffer.h"

#include "stm.h"
#include "httpproxynio.h"
#include "netutils.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))
//#define MSG_NOSIGNAL SO_NOSIGPIPE //sacar en final
enum socks_v5state {

    /**
     * recibe el mensaje `request` del cliente, y lo inicia su proceso
     *
     * Intereses:
     *     - OP_READ sobre client_fd
     *
     * Transiciones:
     *   - REQUEST_READ        mientras el mensaje no esté completo
     *   - REQUEST_RESOLV      se requiere para resolver el hostname
     *   - REQUEST_WRITE       si determinamos que el mensaje no lo podemos
     *                         procesar (ej: no soportamos un comando)
     *   - ERROR               ante cualquier error (IO/parseo)
     */
    REQUEST_READ,

    /**
     * Espera la resolución DNS
     *
     * Intereses:
     *     - OP_NOOP sobre client_fd. Espera un evento de que la tarea bloqueante
     *               terminó.
     * Transiciones:
     *     - REQUEST_CONNECTING si se logra resolución al nombre y se puede
     *                          iniciar la conexión al origin server.
     *     - REQUEST_WRITE      en otro caso
     */
    REQUEST_RESOLV,

    /**
     * Espera que se establezca la conexión al origin server
     *
     * Intereses:
     *    - OP_WRITE sobre client_fd
     *
     * Transiciones:
     *    - REQUEST_WRITE    se haya logrado o no establecer la conexión.
     *
     */
    REQUEST_CONNECTING,

    REQUEST_SEND,

    /**
     * envía la respuesta del `request' al cliente.
     *
     * Intereses:
     *   - OP_WRITE sobre client_fd
     *   - OP_NOOP  sobre origin_fd
     *
     * Transiciones:
     *   - HELLO_WRITE  mientras queden bytes por enviar
     *   - COPY         si el request fue exitoso y tenemos que copiar el
     *                  contenido de los descriptores
     *   - ERROR        ante I/O error
     */
    REQUEST_WRITE,

    // estados terminales
    DONE,
    ERROR,
};

/** usado por REQUEST_READ, REQUEST_WRITE, REQUEST_RESOLV */
struct request_st {
    /** buffer utilizado para I/O */
    buffer                    *rb, *wb;

    /** parser */
    struct http_request             request;
    struct http_parser    		    parser;

    /** el resumen del respuesta a enviar*/
    enum http_response_status status;

    // ¿a donde nos tenemos que conectar?
    struct sockaddr_storage   *origin_addr;
    socklen_t                 *origin_addr_len;
    int                       *origin_domain;

    const int                 *client_fd;
    int                       *origin_fd;
};

/** usado por REQUEST_CONNECTING */
struct connecting {
    buffer     *wb;
    const int  *client_fd;
    int        *origin_fd;
    enum http_response_status *status;
};

struct socks5 {
    /** información del cliente */
    struct sockaddr_storage       client_addr;
    socklen_t                     client_addr_len;
    int                           client_fd;

    /** resolución de la dirección del origin server */
    struct addrinfo              *origin_resolution;
    /** intento actual de la dirección del origin server */
    struct addrinfo              *origin_resolution_current;

    /** información del origin server */
    struct sockaddr_storage       origin_addr;
    socklen_t                     origin_addr_len;
    int                           origin_domain;
    int                           origin_fd;


    /** maquinas de estados */
    struct state_machine          stm;

    /** estados para el client_fd */
    union {
        struct request_st         request;
    } client;
    /** estados para el origin_fd */
    union {
        struct connecting         conn;
    } orig;

    /** buffers para ser usados read_buffer, write_buffer.*/
    uint8_t raw_buff_a[2048], raw_buff_b[2048];
    buffer read_buffer, write_buffer;
    
    /** cantidad de referencias a este objeto. si es uno se debe destruir */
    unsigned references;

    /** siguiente en el pool */
    struct socks5 *next;
};
/**
 * Pool de `struct socks5', para ser reusados.
 *
 * Como tenemos un unico hilo que emite eventos no necesitamos barreras de
 * contención.
 */

static const unsigned  max_pool  = 50; // tamaño máximo
static unsigned        pool_size = 0;  // tamaño actual
static struct socks5 * pool      = 0;  // pool propiamente dicho
static const struct state_definition *
socks5_describe_states(void);

/** crea un nuevo `struct socks5' */
static struct socks5 *
socks5_new(int client_fd) {
    struct socks5 *ret;

    if(pool == NULL) {
        ret = malloc(sizeof(*ret));
    } else {
        ret       = pool;
        pool      = pool->next;
        ret->next = 0;
    }
    if(ret == NULL) {
        goto finally;
    }
    memset(ret, 0x00, sizeof(*ret));

    ret->origin_fd       = -1;
    ret->client_fd       = client_fd;
    ret->client_addr_len = sizeof(ret->client_addr);

    ret->stm    .initial   = REQUEST_READ;
    ret->stm    .max_state = ERROR;
    ret->stm    .states    = socks5_describe_states();
    stm_init(&ret->stm);

    buffer_init(&ret->read_buffer,  N(ret->raw_buff_a), ret->raw_buff_a);
    buffer_init(&ret->write_buffer, N(ret->raw_buff_b), ret->raw_buff_b);

    ret->references = 1;
finally:
    return ret;
}
/** realmente destruye */
static void
socks5_destroy_(struct socks5* s) {
    if(s->origin_resolution != NULL) {
        freeaddrinfo(s->origin_resolution);
        s->origin_resolution = 0;
    }
    free(s);
}

/**
 * destruye un  `struct socks5', tiene en cuenta las referencias
 * y el pool de objetos.
 */
static void
socks5_destroy(struct socks5 *s) {
    if(s == NULL) {
        // nada para hacer
    } else if(s->references == 1) {
        if(s != NULL) {
            if(pool_size < max_pool) {
                s->next = pool;
                pool    = s;
                pool_size++;
            } else {
                socks5_destroy_(s);
            }
        }
    } else {
        s->references -= 1;
    }
}

void
socksv5_pool_destroy(void) {
    struct socks5 *next, *s;
    for(s = pool; s != NULL ; s = next) {
        next = s->next;
        free(s);
    }
}

/** obtiene el struct (socks5 *) desde la llave de selección  */
#define ATTACHMENT(key) ( (struct socks5 *)(key)->data)

/* declaración forward de los handlers de selección de una conexión
 * establecida entre un cliente y el proxy.
 */
static void socksv5_read   (struct selector_key *key);
static void socksv5_write  (struct selector_key *key);
static void socksv5_block  (struct selector_key *key);
static void socksv5_close  (struct selector_key *key);
static const struct fd_handler socks5_handler = {
    .handle_read   = socksv5_read,
    .handle_write  = socksv5_write,
    .handle_close  = socksv5_close,
    .handle_block  = socksv5_block,
};
/** Intenta aceptar la nueva conexión entrante*/
void
socksv5_passive_accept(struct selector_key *key) {
    struct sockaddr_storage       client_addr;
    socklen_t                     client_addr_len = sizeof(client_addr);
    struct socks5                *state           = NULL;

    const int client = accept(key->fd, (struct sockaddr*) &client_addr,
                                                          &client_addr_len);
    if(client == -1) {
        goto fail;
    }
    if(selector_fd_set_nio(client) == -1) {
        goto fail;
    }
    state = socks5_new(client);
    if(state == NULL) {
        // sin un estado, nos es imposible manejaro.
        // tal vez deberiamos apagar accept() hasta que detectemos
        // que se liberó alguna conexión.
        goto fail;
    }
    memcpy(&state->client_addr, &client_addr, client_addr_len);
    state->client_addr_len = client_addr_len;

    if(SELECTOR_SUCCESS != selector_register(key->s, client, &socks5_handler,
                                              OP_READ, state)) {
        goto fail;
    }
    return ;
fail:
    if(client != -1) {
        close(client);
    }
    socks5_destroy(state);
}
////////////////////////////////////////////////////////////////////////////////
// REQUEST
////////////////////////////////////////////////////////////////////////////////

/** inicializa las variables de los estados REQUEST_… */
static void
request_init(const unsigned state, struct selector_key *key) {
    struct request_st * d = &ATTACHMENT(key)->client.request;

    d->rb              = &(ATTACHMENT(key)->read_buffer);
    d->wb              = &(ATTACHMENT(key)->write_buffer);
    d->parser.request  = &d->request;
    d->status          = status_general_proxy_server_failure;
    http_parser_init(&d->parser);
    d->client_fd       = &ATTACHMENT(key)->client_fd;
    d->origin_fd       = &ATTACHMENT(key)->origin_fd;

    d->origin_addr     = &ATTACHMENT(key)->origin_addr;
    d->origin_addr_len = &ATTACHMENT(key)->origin_addr_len;
    d->origin_domain   = &ATTACHMENT(key)->origin_domain;
}

static unsigned
request_process(struct selector_key* key, struct request_st* d);

/** lee todos los bytes del mensaje de tipo `request' y inicia su proceso */
static unsigned
request_read(struct selector_key *key) {
    struct request_st * d = &ATTACHMENT(key)->client.request;

      buffer *b     = d->rb;
    unsigned  ret   = REQUEST_READ;
        bool  error = false;
     uint8_t *ptr;
      size_t  count;
     ssize_t  n;

    ptr = buffer_write_ptr(b, &count);
    n = recv(key->fd, ptr, count, 0);
    if(n > 0) {
        fprintf(stderr, "reading");
        buffer_write_adv(b, n);
        int st = http_consume(b, &d->parser, &error);
        if(http_is_done(st, 0)) {
            fprintf(stderr, "done reading");
            if(error)
                return ERROR;//TODO mejorar esto
            ret = request_process(key, d);
        }
    } else {
        ret = ERROR;
    }

    return error ? ERROR : ret;
}


static unsigned
request_connect(struct selector_key *key, struct request_st * d);

static void *
request_resolv_blocking(void *data);

/**
 * Procesa el mensaje de tipo `request'.
 * Únicamente soportamos el comando cmd_connect.
 *
 * Si tenemos la dirección IP intentamos establecer la conexión.
 *
 * Si tenemos que resolver el nombre (operación bloqueante) disparamos
 * la resolución en un thread que luego notificará al selector que ha terminado.
 *
 */
static unsigned
request_process(struct selector_key* key, struct request_st* d) {
    unsigned  ret;
    pthread_t tid;

    struct selector_key* k = malloc(sizeof(*key));
    if(k == NULL) {
        ret       = REQUEST_WRITE;
        d->status = status_general_proxy_server_failure;
        selector_set_interest_key(key, OP_WRITE);
    } else {
        memcpy(k, key, sizeof(*k));
        if(-1 == pthread_create(&tid, 0,
                        request_resolv_blocking, k)) {
            ret       = REQUEST_WRITE;
            d->status = status_general_proxy_server_failure;
            selector_set_interest_key(key, OP_WRITE);
        } else{
            ret = REQUEST_RESOLV;
            selector_set_interest_key(key, OP_NOOP);
        }
    }

    return ret;
}

/**
 * Realiza la resolución de DNS bloqueante.
 *
 * Una vez resuelto notifica al selector para que el evento esté
 * disponible en la próxima iteración.
 */
static void *
request_resolv_blocking(void *data) {
    struct selector_key *key = (struct selector_key *) data;
    struct socks5       *s   = ATTACHMENT(key);

    pthread_detach(pthread_self());
    s->origin_resolution = 0;
    struct addrinfo hints = {
        .ai_family    = AF_UNSPEC,    /* Allow IPv4 or IPv6 */
        .ai_socktype  = SOCK_STREAM,  /* Datagram socket */
        .ai_flags     = AI_PASSIVE,   /* For wildcard IP address */
        .ai_protocol  = 0,            /* Any protocol */
        .ai_canonname = NULL,
        .ai_addr      = NULL,
        .ai_next      = NULL,
    };

    char buff[7];
    snprintf(buff, sizeof(buff), "%d",
             ntohs(s->client.request.request.dest_port));

    getaddrinfo(s->client.request.request.fqdn, buff, &hints,
               &s->origin_resolution);

    selector_notify_block(key->s, key->fd);

    free(data);
    fprintf(stderr, "resolving");
    return 0;
}

/** procesa el resultado de la resolución de nombres */
static unsigned
request_resolv_done(struct selector_key *key) {
    struct request_st * d = &ATTACHMENT(key)->client.request;
    struct socks5 *s      =  ATTACHMENT(key);

    if(s->origin_resolution == 0) {
        d->status = status_general_proxy_server_failure;
    } else {
        s->origin_domain   = s->origin_resolution->ai_family;
        s->origin_addr_len = s->origin_resolution->ai_addrlen;
        memcpy(&s->origin_addr,
                s->origin_resolution->ai_addr,
                s->origin_resolution->ai_addrlen);
        freeaddrinfo(s->origin_resolution);
        s->origin_resolution = 0;
    }
    fprintf(stderr, "resolved");
    return request_connect(key, d);
}

/** intenta establecer una conexión con el origin server */
static unsigned
request_connect(struct selector_key *key, struct request_st *d) {
    bool error                  = false;
    // da legibilidad
    enum http_response_status status =  d->status;
    int *fd                           =  d->origin_fd;

    *fd = socket(ATTACHMENT(key)->origin_domain, SOCK_STREAM, 0);
    if (*fd == -1) {
        error = true;
        goto finally;
    }
    if (selector_fd_set_nio(*fd) == -1) {
        goto finally;
    }
    if (-1 == connect(*fd, (const struct sockaddr *)&ATTACHMENT(key)->origin_addr,
                           ATTACHMENT(key)->origin_addr_len)) {
        if(errno == EINPROGRESS) {
            // es esperable,  tenemos que esperar a la conexión

            // dejamos de de pollear el socket del cliente
            selector_status st = selector_set_interest_key(key, OP_NOOP);
            if(SELECTOR_SUCCESS != st) {
                error = true;
                goto finally;
            }

            // esperamos la conexion en el nuevo socket
            st = selector_register(key->s, *fd, &socks5_handler,
                                      OP_WRITE, key->data);
            if(SELECTOR_SUCCESS != st) {
                error = true;
                goto finally;
            }
            ATTACHMENT(key)->references += 1;
        } else {
            status = errno_to_socks(errno);
            error = true;
            goto finally;
        }
    } else {
        // estamos conectados sin esperar... no parece posible
        // saltaríamos directamente a COPY
        abort();
    }

finally:
    if (error) {
        if (*fd != -1) {
            close(*fd);
            *fd = -1;
        }
    }

    d->status = status;

    return REQUEST_CONNECTING;
}

static void
request_read_close(const unsigned state, struct selector_key *key) {
    struct request_st * d = &ATTACHMENT(key)->client.request;

    //http_parser_close(&d->parser);
}

////////////////////////////////////////////////////////////////////////////////
// REQUEST CONNECT
////////////////////////////////////////////////////////////////////////////////
static void
request_connecting_init(const unsigned state, struct selector_key *key) {
    struct connecting *d  = &ATTACHMENT(key)->orig.conn;

    d->client_fd = &ATTACHMENT(key)->client_fd;
    d->origin_fd = &ATTACHMENT(key)->origin_fd;
    d->status    = &ATTACHMENT(key)->client.request.status;
    d->wb        = &ATTACHMENT(key)->write_buffer;
}

/** la conexión ha sido establecida (o falló)  */
static unsigned
request_connecting(struct selector_key *key) {
    fprintf(stderr, "connecting");
    int error;
    socklen_t len = sizeof(error);
    struct connecting *d  = &ATTACHMENT(key)->orig.conn;
    struct request_st * d1 = &ATTACHMENT(key)->client.request;
    if (getsockopt(key->fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
        *d->status = status_general_proxy_server_failure;
    } else {
        if(error == 0) {
            *d->status     = status_succeeded;
            *d->origin_fd = key->fd;
        } else {
            *d->status = errno_to_socks(error);
        }
    }

    if(-1 == http_marshall(d->wb, &(d1->request))) {
        *d->status = status_general_proxy_server_failure;
        abort(); // el buffer tiene que ser mas grande en la variable
    }

    selector_status s = 0;
    s |= selector_set_interest_key(key,                   OP_NOOP);
    s |= selector_set_interest    (key->s, *d->origin_fd, OP_WRITE);
    fprintf(stderr, "conectando");
    return SELECTOR_SUCCESS == s ? REQUEST_SEND : ERROR;
}
/*
void
log_request(const enum http_response_status status,
            const struct sockaddr* clientaddr,
            const struct sockaddr* originaddr) {
    char cbuff[SOCKADDR_TO_HUMAN_MIN * 2 + 2 + 32] = { 0 };
    unsigned n = N(cbuff);
    time_t now = 0;
    time(&now);

    // tendriamos que usar gmtime_r pero no está disponible en C99
    strftime(cbuff, n, "%FT%TZ\t", gmtime(&now));
    size_t len = strlen(cbuff);
    sockaddr_to_human(cbuff + len, N(cbuff) - len, clientaddr);
    strncat(cbuff, "\t", n-1);
    cbuff[n-1] = 0;
    len = strlen(cbuff);
    sockaddr_to_human(cbuff + len, N(cbuff) - len, originaddr);

    fprintf(stdout, "%s\tstatus=%d\n", cbuff, status);
}*/

static unsigned
request_send(struct selector_key *key) {
    struct request_st * d = &ATTACHMENT(key)->client.request;

    unsigned  ret       = REQUEST_SEND;
      buffer *b         = d->wb;
     uint8_t *ptr;
      size_t  count;
     ssize_t  n;

    ptr = buffer_read_ptr(b, &count);
    n = send(key->fd, ptr, count, MSG_NOSIGNAL);
    if(n == -1) {
        ret = ERROR;
    } else {
        buffer_read_adv(b, n);

        if(!buffer_can_read(b)) {
            if(d->status == status_succeeded) {
                ret = REQUEST_WRITE;
                selector_set_interest    (key->s,  *d->client_fd, OP_WRITE);
                selector_set_interest    (key->s,  *d->origin_fd, OP_NOOP);
            } else {
                ret = DONE;
                selector_set_interest    (key->s,  *d->client_fd, OP_NOOP);
                if(-1 != *d->origin_fd) {
                    selector_set_interest    (key->s,  *d->origin_fd, OP_NOOP);
                }
            }
        }
    }
fprintf(stderr, "sending");
  //  log_request(d->status, (const struct sockaddr *)&ATTACHMENT(key)->client_addr,
    //                       (const struct sockaddr *)&ATTACHMENT(key)->origin_addr);
    return ret;
}
/** escribe todos los bytes de la respuesta al mensaje `request' */
static unsigned
request_write(struct selector_key *key) {
    struct request_st * d = &ATTACHMENT(key)->client.request;

    unsigned  ret       = REQUEST_WRITE;
      buffer *b         = d->wb;
     uint8_t *ptr;
      size_t  count;
     ssize_t  n;

    ptr = buffer_read_ptr(b, &count);
    n = send(key->fd, ptr, count, MSG_NOSIGNAL);
    if(n == -1) {
        ret = ERROR;
    } else {
        buffer_read_adv(b, n);

        if(!buffer_can_read(b)) {
            if(d->status == status_succeeded) {
                ret = DONE;
                selector_set_interest    (key->s,  *d->client_fd, OP_READ);
                selector_set_interest    (key->s,  *d->origin_fd, OP_NOOP);
            } else {
                ret = DONE;
                selector_set_interest    (key->s,  *d->client_fd, OP_NOOP);
                if(-1 != *d->origin_fd) {
                    selector_set_interest    (key->s,  *d->origin_fd, OP_NOOP);
                }
            }
        }
    }

   // log_request(d->status, (const struct sockaddr *)&ATTACHMENT(key)->client_addr,
     //                      (const struct sockaddr *)&ATTACHMENT(key)->origin_addr);
    return ret;
}

/** definición de handlers para cada estado */
static const struct state_definition client_statbl[] = {
    {
        .state            = REQUEST_READ,
        .on_arrival       = request_init,
        .on_departure     = request_read_close,
        .on_read_ready    = request_read,
    },{
        .state            = REQUEST_RESOLV,
        .on_block_ready   = request_resolv_done,
    },{
        .state            = REQUEST_CONNECTING,
        .on_arrival       = request_connecting_init,
        .on_write_ready   = request_connecting,
    },{
        .state            = REQUEST_SEND,
        .on_write_ready   = request_send,
    },{
        .state            = REQUEST_WRITE,
        .on_write_ready   = request_write,
    }, {
        .state            = DONE,

    },{
        .state            = ERROR,
    }
};
static const struct state_definition *
socks5_describe_states(void) {
    return client_statbl;
}

///////////////////////////////////////////////////////////////////////////////
// Handlers top level de la conexión pasiva.
// son los que emiten los eventos a la maquina de estados.
static void
socksv5_done(struct selector_key* key);

static void
socksv5_read(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_read(stm, key);

    if(ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void
socksv5_write(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_write(stm, key);

    if(ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void
socksv5_block(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_block(stm, key);

    if(ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void
socksv5_close(struct selector_key *key) {
    socks5_destroy(ATTACHMENT(key));
}

static void
socksv5_done(struct selector_key* key) {
    const int fds[] = {
        ATTACHMENT(key)->client_fd,
        ATTACHMENT(key)->origin_fd,
    };
    for(unsigned i = 0; i < N(fds); i++) {
        if(fds[i] != -1) {
            if(SELECTOR_SUCCESS != selector_unregister_fd(key->s, fds[i])) {
                abort();
            }
            close(fds[i]);
        }
    }
}