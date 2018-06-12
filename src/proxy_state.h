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

    /** comando de transformacion */
    char transformation_command[30];
    int transformation_command_index;

    /** comando de transformacion */
    char transformation_types[30];
    int transformation_types_index;

} global_proxy_state;

/** crear estado de proxy */
bool
proxy_state_create();

/** destruir estado de proxy */
void
proxy_state_destroy();