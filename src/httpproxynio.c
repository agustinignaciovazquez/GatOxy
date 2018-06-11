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
#include "logging.h"
#include "stm.h"
#include "httpproxynio.h"
#include "netutils.h"
#include "body_transformation.h"
#include "buffer_size.h"
#include "proxy_state.h"
#include <ctype.h>

global_proxy_state *proxy_state;

#define N(x) (sizeof(x)/sizeof((x)[0]))

void compute_transformation_interests(struct selector_key *key);
bool regexParser(char *regex, char *str);
bool should_filter(uint16_t n, char types[][MAX_TYPES_LEN]);
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
     * Espera la resolucion DNS
     *
     * Intereses:
     *     - OP_NOOP sobre client_fd. Espera un evento de que la tarea 
     *               bloqueante termine
     *
     * Transiciones:
     *     - REQUEST_CONNECTING si se logra resolucion al nombre y se puede
     *                          iniciar la conexion al origin server.
     *     - REQUEST_WRITE      en otro caso
     */
    REQUEST_RESOLV,

    /**
     * Espera que se establezca la conexion al origin server
     *
     * Intereses:
     *    - OP_WRITE sobre client_fd
     *
     * Transiciones:
     *    - REQUEST_WRITE    se haya logrado o no establecer la conexion.
     *
     */
    REQUEST_CONNECTING,


    /**
     * envia la respuesta del `request' al cliente.
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
    struct http_request       request;
    struct http_parser        parser;

    /** el resumen del respuesta a enviar*/
    enum http_response_status status;

    // Â¿a donde nos tenemos que conectar?
    struct sockaddr_storage   *origin_addr;
    socklen_t                 *origin_addr_len;
    int                       *origin_domain;

    const int                 *client_fd;
    int                       *origin_fd;
};

/** estado del parseo de response */
struct response_st{
    /** parser */
    struct http_response                response;
    struct http_res_parser              parser;
};

/** informarcion para la transformacion */
struct transformation_data {
    /** fds para realizar la transformacion */
    int         inputTransformation[2];
    int         outputTransformation[2];

    /** programa que se utilizara para la transformacion */
    char *      prog;

    /** buffer para pasar los datos a transformar */
    buffer      input_buffer;
    uint8_t     raw_input_buffer[DEFAULT_BUFFER_SIZE];
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
    int                         *fd;
    /** el buffer que se utiliza para hacer la copia */
    buffer                      *rb, *wb;
    /** ¿cerramos ya la escritura o la lectura? */
    fd_interest                 duplex;

    int                         client;

    /** estructuras con informacion sobre parseo */
    struct http_request *       request;
    struct response_st          response;

    struct copy *other;

    bool should_filter;

    struct copy *               other;
};

struct socks5 {
    /** informacion del cliente */
    struct sockaddr_storage       client_addr;
    socklen_t                     client_addr_len;
    int                           client_fd;

    /** resolucion de la direccion del origin server */
    struct addrinfo *             origin_resolution;
    /** intento actual de la direccion del origin server */
    struct addrinfo *             origin_resolution_current;

    /** informacion del origin server */
    struct sockaddr_storage       origin_addr;
    socklen_t                     origin_addr_len;
    int                           origin_domain;
    int                           origin_fd;


    buffer *                      headers_copy;

    uint8_t  *                    raw_headers_buffer;

    struct transformation_data *  transformation;

    /** maquinas de estados */
    struct state_machine          stm;

    /** estados para el client_fd */
    struct request_st             client_request;
    struct copy                   client_copy;
    
    /** estados para el origin_fd */
    struct connecting             orig_conn;
    struct copy                   orig_copy;

    /** buffers para transformation */
    uint8_t                       buffer_write_transform[DEFAULT_BUFFER_SIZE
                                                             + 1];
    buffer                        buffer_transform;

    /** buffers para ser usados read_buffer, write_buffer.*/
    uint8_t *                     raw_buff_a;
    uint8_t *                     raw_buff_b;
    buffer                        read_buffer;
    buffer                        write_buffer;
    
    /** cantidad de referencias a este objeto. si es uno se debe destruir */
    unsigned                      references;

    /** siguiente en el pool */
    struct socks5 *               next;
};
/**
 * Pool de `struct socks5', para ser reusados.
 *
 * Como tenemos un unico hilo que emite eventos no necesitamos barreras de
 * contencion.
 */

static const unsigned  max_pool  = 50; // tamano maximo
static unsigned        pool_size = 0;  // tamano actual
static struct socks5 * pool      = 0;  // pool propiamente dicho

static const struct state_definition *
socks5_describe_states(void);

static int 
copy_to_buffer(buffer * source, buffer * b, struct http_res_parser *p);

/** crea un nuevo `struct socks5' */
static struct socks5 *
socks5_new(int client_fd) {

    struct socks5 *ret;
    if(pool == NULL) {
        ret = malloc(sizeof(*ret));
    } 
    else {
        ret = pool;
        pool = pool->next;
        ret->next = 0;
    }
    if(ret == NULL) {
        goto finally;
    }
    memset(ret, 0x00, sizeof(*ret));

    ret->origin_fd = -1;
    ret->client_fd = client_fd;
    ret->client_addr_len = sizeof(ret->client_addr);
    ret->transformation = NULL;

    int buffer_size = get_buffer_size();
    ret->headers_copy = malloc(sizeof(struct buffer));
    ret->raw_headers_buffer = malloc(get_headers_buffer_size() 
                                        * sizeof(uint8_t));
    buffer_init(ret->headers_copy, get_headers_buffer_size() ,
                    ret->raw_headers_buffer);
    ret->raw_buff_a = malloc(buffer_size);
    ret->raw_buff_b = malloc(buffer_size);


    if(ret->raw_buff_a  == NULL || ret->raw_buff_b == NULL){
        ret = NULL;
        goto finally;
    }

    ret->stm    .initial   = REQUEST_READ;
    ret->stm    .max_state = ERROR;
    ret->stm    .states    = socks5_describe_states();

    stm_init(&ret->stm);
    buffer_init(&ret->read_buffer, buffer_size, ret->raw_buff_a);
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
    } 
    else {
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

/** obtiene el struct (socks5 *) desde la llave de seleccion  */
#define ATTACHMENT(key) ( (struct socks5 *)(key)->data)

/** declaracion forward de los handlers de seleccion de una conexion
 *  establecida entre un cliente y el proxy.
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
    .handle_close  = NULL,
    .handle_block  = NULL,
};

/** Intenta aceptar la nueva conexion entrante */
void
socksv5_passive_accept(struct selector_key *key) {

    struct sockaddr_storage       client_addr;
    socklen_t                     client_addr_len = sizeof(client_addr);
    struct socks5 *               state           = NULL;

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
        // sin un estado, nos es imposible manejarlo.
        // tal vez deberiamos apagar accept() hasta que detectemos
        // que se libero alguna conexion.
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

//////////////////////////////////////////////////////////////////////////////
// REQUEST
//////////////////////////////////////////////////////////////////////////////

/** inicializa las variables de los estados REQUEST */
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
    buffer_reset(ATTACHMENT(key)->headers_copy);

}

static unsigned
request_process(struct selector_key* key, struct request_st* d);

/** lee todos los bytes del mensaje de tipo `request' y inicia su proceso */
static unsigned
request_read(struct selector_key *key) {

    struct request_st * d = &ATTACHMENT(key)->client_request;
    buffer *b = d->rb;
    unsigned ret = REQUEST_READ;
    bool error = false;
    uint8_t *ptr;
    size_t count;
    ssize_t n;

    ptr = buffer_write_ptr(b, &count);
    n = recv(key->fd, ptr, count, 0);
    if(n > 0) {
        fprintf(stderr, "reading");
        buffer_write_adv(b, n);
        int st = http_consume(b, &d->parser, &error);
        if(http_is_done(st, 0)) {
            fprintf(stderr, "done reading");
            if(error){
                return ERROR; //TODO mejorar errores
            }
            ret = request_process(key, d);
        }
    } 
    else {
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
 * Unicamente soportamos el comando cmd_connect.
 *
 * Si tenemos la direccion IP intentamos establecer la conexion.
 *
 * Si tenemos que resolver el nombre (operacion bloqueante) disparamos
 * la resolucion en un thread que luego notificara al selector que ha
 * terminado.
 *
 */
static unsigned
request_process(struct selector_key* key, struct request_st* d) {

    unsigned ret;
    pthread_t tid;
    struct selector_key* k = malloc(sizeof(*key));
    if(k == NULL) {
        ret = REQUEST_WRITE;
        d->status = status_general_proxy_server_failure;
        selector_set_interest_key(key, OP_WRITE);
    }
    else {
        memcpy(k, key, sizeof(*k));
        if(-1 == pthread_create(&tid, 0, 
                                    request_resolv_blocking, k)) {
            ret = REQUEST_WRITE;
            d->status = status_general_proxy_server_failure;
            selector_set_interest_key(key, OP_WRITE);
        } 
        else{
            ret = REQUEST_RESOLV;
            selector_set_interest_key(key, OP_NOOP);
        }
    }
    return ret;
}

/**
 * Realiza la resolucion de DNS bloqueante.
 *
 * Una vez resuelto notifica al selector para que el evento esta
 * disponible en la proxima iteracion.
 */
static void *
request_resolv_blocking(void *data) {

    struct selector_key *key = (struct selector_key *) data;
    struct socks5 *s = ATTACHMENT(key);

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
    fprintf(stderr, "Resolving %s:%s\n",s->client_request.request.fqdn, 
                buff); // TODO borrar
    getaddrinfo(s->client_request.request.fqdn, buff, &hints,
                    &s->origin_resolution);

    selector_notify_block(key->s, key->fd);

    free(data);
    
    return 0;
}

/** procesa el resultado de la resolucion de nombres */
static unsigned
request_resolv_done(struct selector_key *key) {

    struct request_st * d = &ATTACHMENT(key)->client_request;
    struct socks5 *s = ATTACHMENT(key);

    if(s->origin_resolution == 0) {
        d->status = status_general_proxy_server_failure;
    } 
    else {
        s->origin_domain = s->origin_resolution->ai_family;
        s->origin_addr_len = s->origin_resolution->ai_addrlen;
        memcpy(&s->origin_addr, s->origin_resolution->ai_addr,
                s->origin_resolution->ai_addrlen);
        freeaddrinfo(s->origin_resolution);
        s->origin_resolution = 0;
    }
    return request_connect(key, d);
}

/** intenta establecer una conexion con el origin server */
static unsigned
request_connect(struct selector_key *key, struct request_st *d) {

    bool error = false;
    enum http_response_status status = d->status;
    int *fd = d->origin_fd;
    *fd = socket(ATTACHMENT(key)->origin_domain, SOCK_STREAM, 0);
    if (*fd == -1) {
        error = true;
        goto finally;
    }
    if (selector_fd_set_nio(*fd) == -1) {
        goto finally;
    }
    if (-1 == connect(*fd, (const struct sockaddr *)
                        &ATTACHMENT(key)->  origin_addr,
                            ATTACHMENT(key)->origin_addr_len)) {
        if(errno == EINPROGRESS) {
            // es esperable,  tenemos que esperar a la conexion
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
        } 
        else {

            error = true;
            goto finally;
        }
    } 
    else {
        d->status = status_server_unreachable;
        selector_set_interest_key(key, OP_WRITE);
        return REQUEST_WRITE;
    }

finally:
    if (error) {
        if (*fd != -1) {
            close(*fd);
            *fd = -1;
            d->status = status_server_unreachable;
        }
        d->status = status_server_unreachable;
        selector_set_interest_key(key, OP_WRITE);
        return REQUEST_WRITE;
    }
    d->status = status;
    return REQUEST_CONNECTING;
}

static void
request_read_close(const unsigned state, struct selector_key *key) {

    struct request_st * d = &ATTACHMENT(key)->client_request;
    http_parser_close(&d->parser); 
}

//////////////////////////////////////////////////////////////////////////////
// REQUEST CONNECT
//////////////////////////////////////////////////////////////////////////////
static void
request_connecting_init(const unsigned state, struct selector_key *key) {

    struct connecting *d = &ATTACHMENT(key)->orig_conn;

    d->client_fd = &ATTACHMENT(key)->client_fd;
    d->origin_fd = &ATTACHMENT(key)->origin_fd;
    d->status = &ATTACHMENT(key)->client_request.status;
    d->wb = &ATTACHMENT(key)->write_buffer;
}

/** la conexion ha sido establecida (o fallo)  */
static unsigned
request_connecting(struct selector_key *key) {

    fprintf(stderr, "connecting"); //TODO borrar
    int error;
    socklen_t len = sizeof(error);
    struct connecting *d  = &ATTACHMENT(key)->orig_conn;
    struct request_st * d1 = &ATTACHMENT(key)->client_request;
    if (getsockopt(key->fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
        *d->status = status_unavailable_service;
        selector_set_interest(key->s,*d->client_fd, OP_WRITE);
        return REQUEST_WRITE;
    } 
    else {
        if(error == 0) {
            *d->status = status_succeeded;
            *d->origin_fd = key->fd;
        } 
        else {
            *d->status = status_server_unreachable;
            selector_set_interest(key->s,*d->client_fd, OP_WRITE);
            return REQUEST_WRITE;
        }
    }
    buffer *b2 = d1->rb;
    if(-1 == http_marshall(ATTACHMENT(key)->headers_copy, &(d1->request),
                             b2)) {
        *d->status = status_general_proxy_server_failure;
        selector_set_interest(key->s,*d->client_fd, OP_WRITE);
        return REQUEST_WRITE; 
    }
    selector_status s = 0;
    s |= selector_set_interest(key->s, *d->client_fd, OP_WRITE);
    s |= selector_set_interest_key(key, OP_READ);
    s |= selector_set_interest (key->s, *d->origin_fd, OP_WRITE);
    fprintf(stderr, "conectando"); //TODO borrar 
    return SELECTOR_SUCCESS == s ? COPY : ERROR;
}

/** escribe todos los bytes de la respuesta al mensaje `request' */
static unsigned
request_write(struct selector_key *key) {

    struct request_st * d = &ATTACHMENT(key)->client_request;
    unsigned ret = REQUEST_WRITE;
    ssize_t n;
    char * msg = "500 ERROR"; // TODO cambiar
    n = send(key->fd,msg, strlen(msg),0);
    if(n == -1) {
        ret = ERROR;
    } else {
        ret = DONE;
        selector_set_interest(key->s,  *d->client_fd, OP_NOOP);
        if(-1 != *d->origin_fd) {
            selector_set_interest(key->s,  *d->origin_fd, OP_NOOP);
        }
    }
    return ret;
}

//////////////////////////////////////////////////////////////////////////////
// RESPONSE
//////////////////////////////////////////////////////////////////////////////

/** inicializa las variables de los estados RESPONSE */
static void
response_init(struct selector_key *key) {

    struct response_st * d = &ATTACHMENT(key)->orig_copy.response;
    d->parser.response = &d->response;
    http_res_parser_init (&d->parser, &ATTACHMENT(key)->buffer_transform);
}

static fd_interest
copy_compute_interests(fd_selector s, struct copy* d);

//////////////////////////////////////////////////////////////////////////////
// COPY
//////////////////////////////////////////////////////////////////////////////

static void
copy_init(const unsigned state, struct selector_key *key) {

    struct copy * d         = &ATTACHMENT(key)->client_copy;
    buffer * buff           = ATTACHMENT(key)->headers_copy;
    d->fd                   = &ATTACHMENT(key)->client_fd;
    d->rb                   = ATTACHMENT(key)->headers_copy;
    buffer_init(&ATTACHMENT(key)->buffer_transform, DEFAULT_BUFFER_SIZE + 1,            ATTACHMENT(key)->buffer_write_transform);
    d->wb                   = &ATTACHMENT(key)->buffer_transform;
    d->duplex               = OP_READ | OP_WRITE;
    d->client               = true;
    d->other                = &ATTACHMENT(key)->orig_copy;


    d                       = &ATTACHMENT(key)->orig_copy;
    d->client               = false;
    d->fd                   = &ATTACHMENT(key)->origin_fd;
    d->rb                   = &ATTACHMENT(key)->write_buffer;
    d->wb                   = ATTACHMENT(key)->headers_copy;
    d->duplex               = OP_READ | OP_WRITE;
    d->other                = &ATTACHMENT(key)->client_copy;

    response_init(key);

}

/**
 * Computa los intereses en base a la disponiblidad de los buffer.
 * La variable duplex nos permite saber si alguna via ya fue cerrada.
 * Arranco OP_READ | OP_WRITE.
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

/** lee bytes de un socket y los encola para ser escritos en otro socket */
static unsigned
copy_r(struct selector_key *key) {

    struct copy * d = copy_ptr(key);
    assert(*d->fd == key->fd);
    size_t size;
    ssize_t n;
    unsigned ret = COPY;
    int * content_length_client = 
                &ATTACHMENT(key)->client_request.request.header_content_length;
    bool  error = false;
    buffer* b = d->rb;
    uint8_t *ptr = buffer_write_ptr(b, &size);
    n = recv(key->fd, ptr, size, 0);
    if(n <= 0) {
        if(!d->client && ATTACHMENT(key)->transformation != NULL ){
            if(!buffer_can_read(b)){
                close(ATTACHMENT(key)->transformation->
                        inputTransformation[WRITE]);
            }
            shutdown(*d->fd, SHUT_RD);
            d->duplex &= ~OP_READ;
        }
        else {
            
            d->duplex = OP_NOOP;
            return DONE;
        }
    }
    else {
        buffer_write_adv(b, n);
        if(!d->client){
            if(http_res_is_done(d->response.parser.state,0) == false){
                int st = http_res_consume(b, &d->response.parser, &error);
                if(http_res_is_done(st, 0)) {
                    fprintf(stderr, "done reading"); //TODO borrar
                    if(error){
                        fprintf(stderr, "error\n" ); //TODO borrar
                        return ERROR;//TODO mejorar esto agregar codigo error
                    }
                    if(proxy_state->do_transform == true && 
                        d->response.parser.is_identity == true && 
                        ATTACHMENT(key)->transformation == NULL && 
                        should_filter(d->response.parser.content_types, d->response.response.content_types)
                        ) {
                        struct transformation_data *t = malloc(sizeof(struct transformation_data));

                        ATTACHMENT(key)->transformation = t;

                        // t->prog = "sed -u -e 's/a/4/g' -e 's/e/3/g' -e 's/i/1/g' -e 's/o/0/g' -e's/5/-/g'";
                        t->prog = proxy_state->transformation_command;

                        buffer_init(&(t->input_buffer), DEFAULT_BUFFER_SIZE, t->raw_input_buffer);

                        selector_status s = SELECTOR_SUCCESS;

                        t->inputTransformation[READ] = -1;
                        t->inputTransformation[WRITE] = -1;
                        t->outputTransformation[READ] = -1;
                        t->outputTransformation[WRITE] = -1;

                        //TODO cambiar nombre
                        int res = process_with_external_program(t->prog, 
                            t->inputTransformation, t->outputTransformation);

                        selector_fd_set_nio(t->inputTransformation[WRITE]);
                        selector_fd_set_nio(t->outputTransformation[READ]);
                        s |= selector_register(key->s, 
                                t->inputTransformation[WRITE], 
                                    &transformation_handler, OP_WRITE,
                                         key->data);
                        s |= selector_register(key->s, 
                                t->outputTransformation[READ], 
                                    &transformation_handler, OP_READ,
                                        key->data);
                        d->response.parser.buffer_output = &t->input_buffer;
                        if (s != SELECTOR_SUCCESS) {
                            printf("HUBO UN ERROR");
                        }
                    }
                }  
                copy_to_buffer(b, d->response.parser.buffer_output,&d->response.parser );
            }else if(!(proxy_state->do_transform == true && d->response.parser.is_identity == true && should_filter(d->response.parser.content_types, d->response.response.content_types) == true)){
                d->rb = d->response.parser.buffer_output;
            }
            copy_to_buffer(b, d->response.parser.buffer_output,
                                &d->response.parser );
        }
    }
    copy_compute_interests(key->s, d);
    copy_compute_interests(key->s, d->other);
    if(ATTACHMENT(key)->transformation != NULL){
        compute_transformation_interests(key);
    }
    if(ret != REQUEST_WRITE && d->other->duplex == OP_NOOP && 
        d->duplex == OP_NOOP) {
        ret = DONE;
    }
    return ret;
}

bool should_filter(uint16_t n, char types[][MAX_TYPES_LEN]) {
    char *aux = calloc(0,sizeof(char));

LOG_DEBUG("#########################");
    for (int i = 0; i < n; i++) {

        LOG_DEBUG(types[i]);
        int size_to_increase = strlen(types[i]);
        aux = realloc(aux, sizeof(aux)+strlen(";")+size_to_increase);
        if (i!=0) strcat(aux, ";");
        strcat(aux, types[i]);
    }
LOG_DEBUG("#########################");
    
    LOG_DEBUG(aux);

    bool ret = regexParser(proxy_state->transformation_types , aux);
    free(aux);
    
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

    if(n == -1 || (n == 0 && size != 0)) {
        shutdown(*d->fd, SHUT_WR);
        d->duplex &= ~OP_WRITE;
        if(*d->other->fd != -1) {
            shutdown(*d->other->fd, SHUT_RD);
            d->other->duplex &= ~OP_READ;
        }
    } 
    else {
        buffer_read_adv(b, n);       
    }
    copy_compute_interests(key->s, d);
    copy_compute_interests(key->s, d->other);
    if(d->duplex == OP_NOOP) {
        ret = DONE;
    }
    return ret;
}

/** definicion de handlers para cada estado */
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
// Handlers top level de la conexion pasiva.
// son los que emiten los eventos a la maquina de estados.

static void
socksv5_done(struct selector_key* key);

static void
socksv5_read(struct selector_key *key) {

    struct state_machine *stm = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_read(stm, key);
    if(ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void
socksv5_write(struct selector_key *key) {

    struct state_machine *stm = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_write(stm, key);
    if(ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void
socksv5_block(struct selector_key *key) {

    struct state_machine *stm = &ATTACHMENT(key)->stm;
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
    if(t != NULL){
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

    if(buffer_can_read(&t->input_buffer) &&  
            t->inputTransformation[WRITE] != -1){
        input |= OP_WRITE;
    }
    if(t->outputTransformation[READ] != -1){
        output |= OP_READ;
    }

    selector_status  s = SELECTOR_SUCCESS;
    if( t->inputTransformation[WRITE] != -1)
        s |= selector_set_interest(key->s, 
                                    t->inputTransformation[WRITE],input);
    if(  t->outputTransformation[READ] != -1)
        s |= selector_set_interest(key->s,
                                    t->outputTransformation[READ], output);
    if(s != SELECTOR_SUCCESS){
        printf("SELECTOR ERROR UNSUCCESSFUL");
    }

}

/** handlers para las transformaciones */
static void 
transformation_read (struct selector_key *key){

    struct transformation_data * t = (ATTACHMENT(key)->transformation);
    size_t n;
    buffer * b = &ATTACHMENT(key)->buffer_transform;
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

    }
    else{
        if(ATTACHMENT(key)->orig_copy.response.parser.is_chunked) {
            int a = sprintf((char*)ptr + count , "%x\r\n",
                                (unsigned int)count);
            buffer_write_adv(b, count + a);
            ATTACHMENT(key)->orig_copy.response.parser.chunked_total_num -=
                                 (count);
            for(int i = 0; i < count; i++){
                const uint8_t c = buffer_read(b);
                buffer_write(b, c);
            }
            buffer_write(b, CR);
            buffer_write(b,LF);
            if(ATTACHMENT(key)->orig_copy.response.parser.chunked_total_num 
                                        <= 0){
                fprintf(stderr, "MANDO END \n"); //TODO borrar
                buffer_write(b, '0');
                buffer_write(b, CR);
                buffer_write(b,LF);
                buffer_write(b, CR);
                buffer_write(b,LF);
            }
        }
        else{
            buffer_write_adv(b, count);
        }

    }
    compute_transformation_interests(key);
    copy_compute_interests(key->s, &ATTACHMENT(key)->client_copy);
    copy_compute_interests(key->s , ATTACHMENT(key)->client_copy.other);
    if(ATTACHMENT(key)->client_copy.duplex == OP_NOOP){
        socksv5_done(key);
    }
}

static void 
transformation_write (struct selector_key *key){

    struct transformation_data * t =(ATTACHMENT(key)->transformation);
    size_t n;
    buffer * b = &(t->input_buffer);
    uint8_t * ptr  = buffer_read_ptr(b, &n);
    t = (ATTACHMENT(key)->transformation);

    int count = write(key->fd,ptr, n );
    if(count <= 0){
        t->inputTransformation[WRITE] = -1;
        selector_unregister_fd(key->s, key->fd);
        if(count == 0)close(key->fd);
    }
    else{
        buffer_read_adv(b, count);
    }
    compute_transformation_interests(key);
    copy_compute_interests(key->s, &ATTACHMENT(key)->client_copy);
    copy_compute_interests(key->s , ATTACHMENT(key)->client_copy.other);
}

static int 
copy_to_buffer(buffer * source, buffer * b, struct http_res_parser *p ){

    enum chunked_state state;
    if( b == source){
        return 0;
    }
    while(buffer_can_read(source)){
         const uint8_t c = buffer_read(source);
         if(p->is_chunked == false || proxy_state->do_transform == false || p->is_identity == false || should_filter(p->content_types, p->response->content_types) == false){
            buffer_write(b, c);
        }
        else{   
            if(p->chunked_state == chunked_body || 
                p->chunked_state == chunked_cr_body ){
                fprintf(stderr, "ESCRIBO %c(%d)\n", c ,c); // TODO Borrar
                buffer_write(b, c);
            }
            state = http_chunked_parser(p,c);
        }
    }
    return 0;
}

bool regexParser(char *regex, char *str) {
    int regex_size = strlen(regex);
    int str_size = strlen(str);
    if (strlen(regex) == 0) return true; // TODO si no tengo regex, matcheo todo????

    int regex_index = 0;
    int str_index = 0;

    int i;
    for (i = 0; i < regex_size; ++i){
        if (tolower(regex[i]) == '*') return true; // wildcard
        if (tolower(str[i]) == ' ') return false; // invalid string str
        if (tolower(regex[i]) == ' ') return false; // invalid string regex
        if (tolower(regex[i]) != tolower(str[i])) return false; // default case, chars should match
        str_index++;
    }

    // valido que los dos el siguiente sea \0
    if (tolower(regex[i]) != tolower(str[str_index])) return false;

    return true;
}