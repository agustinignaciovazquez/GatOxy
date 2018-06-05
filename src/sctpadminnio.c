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
#include "buffer_size.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))

enum sctpCli_state {

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

/** usado por REQUEST_READ, REQUEST_WRITE */
struct request_st {
    /** buffer utilizado para I/O */
    buffer                    *rb, *wb;

    /** parser */
    struct http_request             request;
    struct http_parser    		    parser;

    /** el resumen del respuesta a enviar*/
    enum http_response_status status;

    const int                 *client_fd;
};

/** usado por COPY */
struct copy {
    /** el otro file descriptor */
    int         *fd;
    /** el buffer que se utiliza para hacer la copia */
    buffer      *rb, *wb;
    /** ¿cerramos ya la escritura o la lectura? */
    fd_interest duplex;

    int        client;

    struct copy *other;
};

struct sctpCli {
    /** información del cliente */
    struct sockaddr_storage       client_addr;
    socklen_t                     client_addr_len;
    int                           client_fd;

    buffer                   *headers_copy;

    /** maquinas de estados */
    struct state_machine          stm;

    /** estados para el client_fd */
    union {
        struct request_st         request;
        struct copy               copy;
    } client;

    /** buffers para ser usados read_buffer, write_buffer.*/
    uint8_t * raw_buff_a, * raw_buff_b;
    buffer read_buffer, write_buffer;
    
    /** cantidad de referencias a este objeto. si es uno se debe destruir */
    unsigned references;

    /** siguiente en el pool */
    struct sctpCli *next;
};
/**
 * Pool de `struct sctpCli', para ser reusados.
 *
 * Como tenemos un unico hilo que emite eventos no necesitamos barreras de
 * contención.
 */

static const unsigned  max_pool  = 50; // tamaño máximo
static unsigned        pool_size = 0;  // tamaño actual
static struct sctpCli * pool      = 0;  // pool propiamente dicho
static const struct state_definition *
sctp_describe_states(void);

/** crea un nuevo `struct sctpCli' */
static struct sctpCli *
sctpCli_new(int client_fd) {
    struct sctpCli *ret;

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
    
    ret->client_fd       = client_fd;
    ret->client_addr_len = sizeof(ret->client_addr);

    int buffer_size = get_buffer_size();

    ret->raw_buff_a = malloc(buffer_size);
    ret->raw_buff_b = malloc(buffer_size);

    if(ret->raw_buff_a  == NULL || ret->raw_buff_b == NULL)
    {
        ret = NULL;
        goto finally;
    }

    ret->stm    .initial   = REQUEST_READ;
    ret->stm    .max_state = ERROR;
    ret->stm    .states    = sctp_describe_states();

    stm_init(&ret->stm);


    buffer_init(&ret->read_buffer,  buffer_size, ret->raw_buff_a);
    buffer_init(&ret->write_buffer, buffer_size, ret->raw_buff_b);

    ret->references = 1;
finally:
    return ret;
}
/** realmente destruye */
static void
sctpCli_destroy_(struct sctpCli* s) {
    free(s);
}

/**
 * destruye un  `struct sctpCli', tiene en cuenta las referencias
 * y el pool de objetos.
 */
static void
sctpCli_destroy(struct sctpCli *s) {
    if(s == NULL) {
        // nada para hacer
    } else if(s->references == 1) {
        if(s != NULL) {
            if(pool_size < max_pool) {
                s->next = pool;
                pool    = s;
                pool_size++;
            } else {
                sctpCli_destroy_(s);
            }
        }
    } else {
        s->references -= 1;
    }
}

void
sctp_pool_destroy(void) {
    struct sctpCli *next, *s;
    for(s = pool; s != NULL ; s = next) {
        next = s->next;
        free(s);
    }
}

/** obtiene el struct (sctpCli *) desde la llave de selección  */
#define ATTACHMENT(key) ( (struct sctpCli *)(key)->data)

/* declaración forward de los handlers de selección de una conexión
 * establecida entre un cliente y el proxy.
 */
static void sctpCli_read   (struct selector_key *key);
static void sctpCli_write  (struct selector_key *key);
static void sctpCli_block  (struct selector_key *key);
static void sctpCli_close  (struct selector_key *key);

static const struct fd_handler sctpCli_handler = {
    .handle_read   = sctpCli_read,
    .handle_write  = sctpCli_write,
    .handle_close  = sctpCli_close,
    .handle_block  = sctpCli_block,
};

/** Intenta aceptar la nueva conexión entrante*/
void
sctp_passive_accept(struct selector_key *key) {
    struct sockaddr_storage       client_addr;
    socklen_t                     client_addr_len = sizeof(client_addr);
    struct sctpCli                *state           = NULL;

    const int client = accept(key->fd, (struct sockaddr*) &client_addr,
                                                          &client_addr_len);
    if(client == -1) {
        goto fail;
    }
    if(selector_fd_set_nio(client) == -1) {
        goto fail;
    }
    state = sctpCli_new(client);
    if(state == NULL) {
        // sin un estado, nos es imposible manejaro.
        // tal vez deberiamos apagar accept() hasta que detectemos
        // que se liberó alguna conexión.
        printf("Connection failed \n");
        goto fail;
    }
    memcpy(&state->client_addr, &client_addr, client_addr_len);
    state->client_addr_len = client_addr_len;

    if(SELECTOR_SUCCESS != selector_register(key->s, client, &sctpCli_handler,
                                              OP_READ, state)) {
        printf("Selector is full \n");
        goto fail;
    }
    return ;
fail:
    if(client != -1) {
        close(client);
    }
    sctpCli_destroy(state);
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

}

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
            // ret = request_process(key, d);
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

static void
request_read_close(const unsigned state, struct selector_key *key) {
    struct request_st * d = &ATTACHMENT(key)->client.request;

    //http_parser_close(&d->parser);
}

////////////////////////////////////////////////////////////////////////////////
// REQUEST CONNECT
////////////////////////////////////////////////////////////////////////////////


/**
 * Computa los intereses en base a la disponiblidad de los buffer.
 * La variable duplex nos permite saber si alguna vía ya fue cerrada.
 * Arrancá OP_READ | OP_WRITE.
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
    struct copy * d = &ATTACHMENT(key)->client.copy;

    if(*d->fd == key->fd) {
        // ok
    } else {
        d = d->other;
    }
    return  d;
}

/** definición de handlers para cada estado */
static const struct state_definition sctp_client_statbl[] = {
   {
        .state            = REQUEST_READ,
        .on_arrival       = request_init,
        .on_departure     = request_read_close,
        .on_read_ready    = request_read,
    }, {
        .state            = DONE,

    },{
        .state            = ERROR,
    }
};
static const struct state_definition *
sctp_describe_states(void) {
    return sctp_client_statbl;
}

///////////////////////////////////////////////////////////////////////////////
// Handlers top level de la conexión pasiva.
// son los que emiten los eventos a la maquina de estados.
static void
sctpCli_done(struct selector_key* key);

static void
sctpCli_read(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum sctpCli_state st = stm_handler_read(stm, key);

    if(ERROR == st || DONE == st) {
        sctpCli_done(key);
    }
}

static void
sctpCli_write(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum sctpCli_state st = stm_handler_write(stm, key);

    if(ERROR == st || DONE == st) {
        sctpCli_done(key);
    }
}

static void
sctpCli_block(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum sctpCli_state st = stm_handler_block(stm, key);

    if(ERROR == st || DONE == st) {
        sctpCli_done(key);
    }
}

static void
sctpCli_close(struct selector_key *key) {
    sctpCli_destroy(ATTACHMENT(key));
}

static void
sctpCli_done(struct selector_key* key) {
    const int fds[] = {
        ATTACHMENT(key)->client_fd,
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