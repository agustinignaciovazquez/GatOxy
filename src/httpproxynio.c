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
#include "HTTPResponsev2.h"

#include "stm.h"
#include "httpproxynio.h"
#include "netutils.h"
#include "body_transformation.h"
#include "buffer_size.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))
void
compute_transformation_interests(struct selector_key *key);
//#define MSG_NOSIGNAL SO_NOSIGPIPE //sacar en final
enum socks_v5state {

    /**
     * recibe el mensaje `request` del cliente, y lo inicia su proceso
     *
     * Intereses:
     *     - OP_READ sobre client_fd
     *
     * Transiciones:
     *   - REQUEST_READ        mientras el mensaje no estÃ© completo
     *   - REQUEST_RESOLV      se requiere para resolver el hostname
     *   - REQUEST_WRITE       si determinamos que el mensaje no lo podemos
     *                         procesar (ej: no soportamos un comando)
     *   - ERROR               ante cualquier error (IO/parseo)
     */
    REQUEST_READ,

    /**
     * Espera la resoluciÃ³n DNS
     *
     * Intereses:
     *     - OP_NOOP sobre client_fd. Espera un evento de que la tarea bloqueante
     *               terminÃ³.
     * Transiciones:
     *     - REQUEST_CONNECTING si se logra resoluciÃ³n al nombre y se puede
     *                          iniciar la conexiÃ³n al origin server.
     *     - REQUEST_WRITE      en otro caso
     */
    REQUEST_RESOLV,

    /**
     * Espera que se establezca la conexiÃ³n al origin server
     *
     * Intereses:
     *    - OP_WRITE sobre client_fd
     *
     * Transiciones:
     *    - REQUEST_WRITE    se haya logrado o no establecer la conexiÃ³n.
     *
     */
    REQUEST_CONNECTING,


    /**
     * envÃ­a la respuesta del `request' al cliente.
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
    /**
     * Copia bytes entre client_fd y origin_fd.
     *
     * Intereses: (tanto para client_fd y origin_fd)
     *   - OP_READ  si hay espacio para escribir en el buffer de lectura
     *   - OP_WRITE si hay bytes para leer en el buffer de escritura
     *
     * Transicion:
     *   - DONE     cuando no queda nada mas por copiar.
     */
    COPY,
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
    struct http_parser              parser;

    /** el resumen del respuesta a enviar*/
    enum http_response_status status;

    // Â¿a donde nos tenemos que conectar?
    struct sockaddr_storage   *origin_addr;
    socklen_t                 *origin_addr_len;
    int                       *origin_domain;

    const int                 *client_fd;
    int                       *origin_fd;
};

struct response_st{

    struct http_response             response;

    struct http_res_parser              parser;

};

struct transformation_data {

    int inputTransformation[2];
    int outputTransformation[2];

    char * prog;

    bool input ,output;

    buffer  input_buffer;
    buffer  output_buffer;

    uint8_t  raw_input_buffer[50];
    uint8_t  raw_output_buffer[50];
};


/** usado por REQUEST_CONNECTING */
struct connecting {
    buffer     *wb;
    const int  *client_fd;
    int        *origin_fd;
    enum http_response_status *status;
};

/** usado por COPY */
struct copy {
    /** el otro file descriptor */
    int         *fd;
    /** el buffer que se utiliza para hacer la copia */
    buffer      *rb, *wb;
    /** Â¿cerramos ya la escritura o la lectura? */
    fd_interest duplex;

    int        client;

    struct http_request * request;

    struct response_st response;

    struct copy *other;
};

struct socks5 {
    /** informaciÃ³n del cliente */
    struct sockaddr_storage       client_addr;
    socklen_t                     client_addr_len;
    int                           client_fd;

    /** resoluciÃ³n de la direcciÃ³n del origin server */
    struct addrinfo              *origin_resolution;
    /** intento actual de la direcciÃ³n del origin server */
    struct addrinfo              *origin_resolution_current;

    /** informaciÃ³n del origin server */
    struct sockaddr_storage       origin_addr;
    socklen_t                     origin_addr_len;
    int                           origin_domain;
    int                           origin_fd;


    buffer                   *headers_copy;

    uint8_t  * raw_headers_buffer;

    struct transformation_data * transformation;

    /** maquinas de estados */
    struct state_machine          stm;

    /** estados para el client_fd */
    struct request_st         client_request;
    struct copy           client_copy;
    
    /** estados para el origin_fd */
    struct connecting         orig_conn;
    struct copy               orig_copy;

    /** buffers para ser usados read_buffer, write_buffer.*/
    uint8_t * raw_buff_a, * raw_buff_b;
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
 * contenciÃ³n.
 */

static const unsigned  max_pool  = 50; // tamaÃ±o mÃ¡ximo
static unsigned        pool_size = 0;  // tamaÃ±o actual
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


    ret->transformation = NULL;

    int buffer_size = get_buffer_size();
    ret->headers_copy = malloc(sizeof(struct buffer));
    ret->raw_headers_buffer = malloc(1024 * sizeof(uint8_t));
    buffer_init(ret->headers_copy, 1024,ret->raw_headers_buffer);

    ret->raw_buff_a = malloc(buffer_size);
    ret->raw_buff_b = malloc(buffer_size);


    if(ret->raw_buff_a  == NULL || ret->raw_buff_b == NULL)
    {
        ret = NULL;
        goto finally;
    }

    ret->stm    .initial   = REQUEST_READ;
    ret->stm    .max_state = ERROR;
    ret->stm    .states    = socks5_describe_states();

    stm_init(&ret->stm);


    buffer_init(&ret->read_buffer,  buffer_size, ret->raw_buff_a);
    buffer_init(&ret->write_buffer, buffer_size, ret->raw_buff_b);

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

/** obtiene el struct (socks5 *) desde la llave de selecciÃ³n  */
#define ATTACHMENT(key) ( (struct socks5 *)(key)->data)

/* declaraciÃ³n forward de los handlers de selecciÃ³n de una conexiÃ³n
 * establecida entre un cliente y el proxy.
 */
static void socksv5_read   (struct selector_key *key);
static void socksv5_write  (struct selector_key *key);
static void socksv5_block  (struct selector_key *key);
static void socksv5_close  (struct selector_key *key);
static void transformation_read (struct selector_key *key);
static void transformation_write (struct selector_key *key);
static const struct fd_handler socks5_handler = {
    .handle_read   = socksv5_read,
    .handle_write  = socksv5_write,
    .handle_close  = socksv5_close,
    .handle_block  = socksv5_block,
};
static const struct fd_handler transformation_handler = {
        .handle_read   = transformation_read,
        .handle_write  = transformation_write,
};

/** Intenta aceptar la nueva conexiÃ³n entrante*/
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
        // que se liberÃ³ alguna conexiÃ³n.
        printf("Connection failed \n");
        goto fail;
    }
    memcpy(&state->client_addr, &client_addr, client_addr_len);
    state->client_addr_len = client_addr_len;

    if(SELECTOR_SUCCESS != selector_register(key->s, client, &socks5_handler,
                                              OP_READ, state)) {
        printf("Selector is full \n");
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

/** inicializa las variables de los estados REQUEST_â€¦ */
static void
request_init(const unsigned state, struct selector_key *key) {
    struct request_st * d = &ATTACHMENT(key)->client_request;

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
    struct request_st * d = &ATTACHMENT(key)->client_request;

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
 * Ãšnicamente soportamos el comando cmd_connect.
 *
 * Si tenemos la direcciÃ³n IP intentamos establecer la conexiÃ³n.
 *
 * Si tenemos que resolver el nombre (operaciÃ³n bloqueante) disparamos
 * la resoluciÃ³n en un thread que luego notificarÃ¡ al selector que ha terminado.
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
 * Realiza la resoluciÃ³n de DNS bloqueante.
 *
 * Una vez resuelto notifica al selector para que el evento estÃ©
 * disponible en la prÃ³xima iteraciÃ³n.
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
             ntohs(s->client_request.request.dest_port));
    fprintf(stderr, "\nresolving %s:%s\n",s->client_request.request.fqdn, buff);
    getaddrinfo(s->client_request.request.fqdn, buff, &hints,
               &s->origin_resolution);

    selector_notify_block(key->s, key->fd);

    free(data);
    
    return 0;
}

/** procesa el resultado de la resoluciÃ³n de nombres */
static unsigned
request_resolv_done(struct selector_key *key) {
    struct request_st * d = &ATTACHMENT(key)->client_request;
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

/** intenta establecer una conexiÃ³n con el origin server */
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
            // es esperable,  tenemos que esperar a la conexiÃ³n

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
        // saltarÃ­amos directamente a COPY
        abort();
    }

finally:
    fprintf(stderr, "FINALLY CONNECT\n" );
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
    struct request_st * d = &ATTACHMENT(key)->client_request;

    //http_parser_close(&d->parser);
}

////////////////////////////////////////////////////////////////////////////////
// REQUEST CONNECT
////////////////////////////////////////////////////////////////////////////////
static void
request_connecting_init(const unsigned state, struct selector_key *key) {
    struct connecting *d  = &ATTACHMENT(key)->orig_conn;

    d->client_fd = &ATTACHMENT(key)->client_fd;
    d->origin_fd = &ATTACHMENT(key)->origin_fd;
    d->status    = &ATTACHMENT(key)->client_request.status;
    d->wb        = &ATTACHMENT(key)->write_buffer;
}

/** la conexiÃ³n ha sido establecida (o fallÃ³)  */
static unsigned
request_connecting(struct selector_key *key) {
    fprintf(stderr, "connecting");
    int error;
    socklen_t len = sizeof(error);
    struct connecting *d  = &ATTACHMENT(key)->orig_conn;
    struct request_st * d1 = &ATTACHMENT(key)->client_request;
    if (getsockopt(key->fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
        selector_set_interest(key->s,key->fd, OP_WRITE);
        return REQUEST_WRITE;
    } else {
        if(error == 0) {
            *d->status     = status_succeeded;
            *d->origin_fd = key->fd;
        } else {
            //*d->status = errno_to_socks(error);
            selector_set_interest(key->s,key->fd, OP_WRITE);
            return REQUEST_WRITE;
        }
    }
    buffer *b2   = d1->rb;
    if(-1 == http_marshall(ATTACHMENT(key)->headers_copy, &(d1->request), b2)) {
        *d->status = status_general_proxy_server_failure;
        abort(); // el buffer tiene que ser mas grande en la variable
    }

    selector_status s = 0;
    s |= selector_set_interest    (key->s, *d->client_fd, OP_WRITE);
    s |= selector_set_interest_key(key,                   OP_READ);
    s |= selector_set_interest    (key->s, *d->origin_fd, OP_WRITE);
    fprintf(stderr, "conectando");
    return SELECTOR_SUCCESS == s ? COPY : ERROR;
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

    // tendriamos que usar gmtime_r pero no estÃ¡ disponible en C99
    strftime(cbuff, n, "%FT%TZ\t", gmtime(&now));
    size_t len = strlen(cbuff);
    sockaddr_to_human(cbuff + len, N(cbuff) - len, clientaddr);
    strncat(cbuff, "\t", n-1);
    cbuff[n-1] = 0;
    len = strlen(cbuff);
    sockaddr_to_human(cbuff + len, N(cbuff) - len, originaddr);

    fprintf(stdout, "%s\tstatus=%d\n", cbuff, status);
}*/


/** escribe todos los bytes de la respuesta al mensaje `request' */
static unsigned
request_write(struct selector_key *key) {
    struct request_st * d = &ATTACHMENT(key)->client_request;

    unsigned  ret       = REQUEST_WRITE;
    buffer *b         = d->wb;
    uint8_t *ptr;
    size_t  count;
    ssize_t  n;
    char * msg = "ERROR 500 WACHO";
   // ptr = buffer_read_ptr(b, &count);
    n = send(key->fd,msg, strlen(msg),0);
   // n = send(key->fd, ptr, count, MSG_NOSIGNAL);
    if(n == -1) {
        ret = ERROR;
    } else {
        buffer_read_adv(b, n);

        if(!buffer_can_read(b)) {
            if(d->status == status_succeeded) {
                ret = DONE;
                selector_set_interest    (key->s,  *d->client_fd, OP_NOOP);
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

////////////////////////////////////////////////////////////////////////////////
// RESPONSE
////////////////////////////////////////////////////////////////////////////////

/** inicializa las variables de los estados RESPONSE_â€¦ */
static void
response_init(struct selector_key *key) {
    struct response_st * d = &ATTACHMENT(key)->orig_copy.response;
    d->parser.response  = &d->response;
    http_res_parser_init (&d->parser);
}

static fd_interest
copy_compute_interests(fd_selector s, struct copy* d);
////////////////////////////////////////////////////////////////////////////////
// COPY
////////////////////////////////////////////////////////////////////////////////

static void
copy_init(const unsigned state, struct selector_key *key) {
    struct copy * d = &ATTACHMENT(key)->client_copy;
    buffer * buff = ATTACHMENT(key)->headers_copy;
    d->fd        = &ATTACHMENT(key)->client_fd;
    d->rb        = ATTACHMENT(key)->headers_copy;
    d->wb        = &ATTACHMENT(key)->write_buffer;//->write_buffer;
    d->duplex    = OP_READ | OP_WRITE;
    d->client    = true;
    d->other     = &ATTACHMENT(key)->orig_copy;


    d = &ATTACHMENT(key)->orig_copy;
    d->client   = false;
    d->fd       = &ATTACHMENT(key)->origin_fd;
    d->rb       = &ATTACHMENT(key)->write_buffer;
    d->wb       = ATTACHMENT(key)->headers_copy;
    d->duplex   = OP_READ | OP_WRITE;
    d->other    = &ATTACHMENT(key)->client_copy;

    response_init(key);

}

/**
 * Computa los intereses en base a la disponiblidad de los buffer.
 * La variable duplex nos permite saber si alguna vÃ­a ya fue cerrada.
 * ArrancÃ¡ OP_READ | OP_WRITE.
 */
static fd_interest
copy_compute_interests(fd_selector s, struct copy* d) {
    fd_interest ret = OP_NOOP;
    if ((d->duplex & OP_READ)  && buffer_can_write(d->rb)) {
        ret |= OP_READ;
    }
    if ((d->duplex & OP_WRITE) && buffer_can_read (d->wb)) {
        ret |= OP_WRITE;
    }
    selector_status status = selector_set_interest(s, *d->fd, ret);
    if(SELECTOR_SUCCESS != status) {
        abort();
    }
    return ret;
}

/** elige la estructura de copia correcta de cada fd (origin o client) */
static struct copy *
copy_ptr(struct selector_key *key) {
    struct copy * d = &ATTACHMENT(key)->client_copy;

    if(*d->fd == key->fd) {
        // ok
    } else {
        d = d->other;
    }
    return  d;
}

bool transform = false;

/** lee bytes de un socket y los encola para ser escritos en otro socket */
static unsigned
copy_r(struct selector_key *key) {
    struct copy * d = copy_ptr(key);

    assert(*d->fd == key->fd);

    size_t size;
    ssize_t n;

    unsigned ret = COPY;

    int * content_length_client = &ATTACHMENT(key)->client_request.request.header_content_length;

    bool  error = false;


    if(!d->client)
    {
        if(transform && ATTACHMENT(key)->transformation == NULL) {
            struct transformation_data *t = malloc(sizeof(struct transformation_data));

            ATTACHMENT(key)->transformation = t;

            t->prog = "cat";

            buffer_init(&(t->input_buffer), 50, t->raw_input_buffer);
            buffer_init(&(t->output_buffer), 50, t->raw_output_buffer);

            d->rb = &t->input_buffer;
            d->other->wb = &t->output_buffer;
            selector_status s = SELECTOR_SUCCESS;

            t->inputTransformation[READ] = -1;
            t->inputTransformation[WRITE] = -1;

            t->outputTransformation[READ] = -1;
            t->outputTransformation[WRITE] = -1;
            t->input = true;
            t->output = true;

            int res = process_with_external_program(t->prog, t->inputTransformation, t->outputTransformation);


            s |= selector_register(key->s, t->inputTransformation[WRITE], &transformation_handler, OP_WRITE, key->data);
            s |= selector_register(key->s, t->outputTransformation[READ], &transformation_handler, OP_READ, key->data);


            if (s != SELECTOR_SUCCESS) {
                printf("HUBO UN ERROR");
            }
        }
    }
    buffer* b    = d->rb;
    uint8_t *ptr = buffer_write_ptr(b, &size);

    n = recv(key->fd, ptr, size, 0);
    if(n <= 0) {
        if(!d->client && ATTACHMENT(key)->transformation != NULL )
        {
            if(!buffer_can_read(b))
                close(ATTACHMENT(key)->transformation->inputTransformation[WRITE]);
            shutdown(*d->fd, SHUT_RD);
            d->duplex &= ~OP_READ;
        }else {
            
            d->duplex = OP_NOOP;
            return DONE;
        }
    } else {
        //if(d->client){
           // *content_length_client -= n;
           // fprintf(stderr,"n es %d", *content_length_client);
        // } 
        buffer_write_adv(b, n);
        if(!d->client){
            if(http_res_is_done(d->response.parser.state,0) == false){
                //buffer_write_adv(b, n);
                int st = http_res_consume(b, &d->response.parser, &error);
                if(http_res_is_done(st, 0)) {
                    fprintf(stderr, "done reading");
                    if(error){
                        fprintf(stderr, "error wachen\n" );
                        return ERROR;//TODO mejorar esto
                    }
                    if(-1 ==  http_res_marshall(d->other->wb, &(d->response.response))) {
                        //*d->status = status_general_proxy_server_failure;
                        fprintf(stderr, "aborto ilegal\n"  );
                        //abort(); // el buffer tiene que ser mas grande en la variable
                    }
                    d->response.parser.content_length -= n;
                    if (d->response.parser.content_length<=0){
                        response_init(key);
                    }
                }  
            }
            
        }
    }
    copy_compute_interests(key->s, d);
    copy_compute_interests(key->s, d->other);
    if(ATTACHMENT(key)->transformation != NULL)
    {
        compute_transformation_interests(key);
    }
    if(d->duplex == OP_NOOP) {
        ret = DONE;
    }
    return ret;
}

/** escribe bytes encolados */
static unsigned
copy_w(struct selector_key *key) {
    struct copy * d = copy_ptr(key);

    assert(*d->fd == key->fd);
    size_t size;
    ssize_t n;
    buffer* b = d->wb;
    unsigned ret = COPY;

    uint8_t *ptr = buffer_read_ptr(b, &size);
    n = send(key->fd, ptr, size, 0);

    if(n == -1) {
        shutdown(*d->fd, SHUT_WR);
        d->duplex &= ~OP_WRITE;
        if(*d->other->fd != -1) {
            shutdown(*d->other->fd, SHUT_RD);
            d->other->duplex &= ~OP_READ;
        }
    } else {
        buffer_read_adv(b, n);
        if(d->client && ATTACHMENT(key)->transformation != NULL)
        {
            if(!buffer_can_read(b) && ATTACHMENT(key)->transformation->outputTransformation[READ] == -1)
            {
                  d->duplex = OP_NOOP;
            }
            compute_transformation_interests(key);
        }
    }
    copy_compute_interests(key->s, d);
    copy_compute_interests(key->s, d->other);

    if(d->duplex == OP_NOOP) {
        ret = DONE;
    }
    return ret;
}
/** definiciÃ³n de handlers para cada estado */
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
        .state            = REQUEST_WRITE,
        .on_write_ready   = request_write,
    }, {
        .state            = COPY,
        .on_arrival       = copy_init,
        .on_read_ready    = copy_r,
        .on_write_ready   = copy_w,
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
// Handlers top level de la conexiÃ³n pasiva.
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
    struct transformation_data * t = ATTACHMENT(key)->transformation;
    if(t != NULL)
    {
        if(t->outputTransformation[READ] != -1) {
            close(t->outputTransformation[READ]);
            selector_unregister_fd(key->s,t->outputTransformation[READ] );
        }
        if(t->inputTransformation[WRITE] != -1) {
            close(t->inputTransformation[WRITE]);
            selector_unregister_fd(key->s,t->inputTransformation[WRITE] );
        }
    }
}

void
compute_transformation_interests(struct selector_key *key) {

    struct transformation_data * t = (ATTACHMENT(key)->transformation);
    fd_interest input = OP_NOOP;
    fd_interest output = OP_NOOP;

    if(buffer_can_read(&t->input_buffer) &&  t->inputTransformation[WRITE] != -1)
    {
        input |= OP_WRITE;
    }
    if(buffer_can_write(&t->output_buffer) && t->outputTransformation[READ] != -1)
    {
        output |= OP_READ;
    }

    selector_status  s = SELECTOR_SUCCESS;
    if( t->inputTransformation[WRITE] != -1)
        s |= selector_set_interest(key->s, t->inputTransformation[WRITE],input);
    if(  t->outputTransformation[READ] != -1)
        s |= selector_set_interest(key->s, t->outputTransformation[READ], output);

    if(s != SELECTOR_SUCCESS)
    {
        printf("ERRORR MUY GRAVE");
    }

}

//transformation handlers

static void transformation_read (struct selector_key *key)
{
    struct transformation_data * t = (ATTACHMENT(key)->transformation);
    size_t n;
    buffer * b = &(t->output_buffer);
    uint8_t * ptr = buffer_write_ptr(b, &n);

    t = (ATTACHMENT(key)->transformation);
    int count = read(key->fd,ptr, n );
    if(count <= 0){
        t->outputTransformation[READ] = -1;
        selector_unregister_fd(key->s, key->fd);
        if(count == 0)close(key->fd);
        if(!buffer_can_read(b))
        {
            shutdown(*ATTACHMENT(key)->client_copy.fd, SHUT_WR);
            ATTACHMENT(key)->client_copy.duplex = OP_NOOP;
        }

    }else{
            buffer_write_adv(b, count);
            compute_transformation_interests(key);
    }

    copy_compute_interests(key->s, &ATTACHMENT(key)->client_copy);
    copy_compute_interests(key->s , ATTACHMENT(key)->client_copy.other);

    if(ATTACHMENT(key)->client_copy.duplex == OP_NOOP){
        socksv5_done(key);
    }


}
static void transformation_write (struct selector_key *key)
{
    struct transformation_data * t =(ATTACHMENT(key)->transformation);
    size_t n;

    buffer * b = &(t->input_buffer);

    uint8_t * ptr  = buffer_read_ptr(b, &n);

    t = (ATTACHMENT(key)->transformation);


    int count = write(key->fd,ptr, n );

    if(count <= 0)
    {
        t->inputTransformation[WRITE] = -1;
        selector_unregister_fd(key->s, key->fd);
        if(count == 0)close(key->fd);
    }else{
            buffer_read_adv(b, count);
        compute_transformation_interests(key);
        if((ATTACHMENT(key)->orig_copy.duplex && OP_READ) != OP_READ && !buffer_can_read(b))
        {
            t->inputTransformation[WRITE] = -1;
            selector_unregister_fd(key->s, key->fd);
            close(key->fd);
        }

    }

    copy_compute_interests(key->s, &ATTACHMENT(key)->client_copy);
    copy_compute_interests(key->s , ATTACHMENT(key)->client_copy.other);
}
