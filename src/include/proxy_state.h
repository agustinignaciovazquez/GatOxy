#include <stdlib.h>
#include <stdbool.h>

/**
 * proxystate -- toma las metricas del uso del proxy
 */

/** estado general del proxy */
typedef struct global_proxy_state {

    /** registrar la cantidad de bytes transferidos */
    unsigned bytesTransfered;
    
    /** ports de escucha */
    unsigned port;
    unsigned confPort;

    /** flag de transformacion */
    bool do_transform;

    /** transformation command */
    char *transformation_command;
    int transformation_command_index;

    /** transformation command */
    char *transformation_types;
    int transformation_types_index;

    /** filters stderr */
    char *filters_stderr;

    /** interfaz http */
    int http_interface;

    /** interfaz proxy */
    int proxy_interface;

    /** buffer */
    unsigned buffer;

    /** request count */
    unsigned request_count;

    /** byte count */
    unsigned byte_count;

    /** total current connections */
    unsigned live_connections;

} global_proxy_state;

/** crear estado de proxy */
bool
proxy_state_create(int argc, char **argv);

/** destruir estado de proxy */
void
proxy_state_destroy();