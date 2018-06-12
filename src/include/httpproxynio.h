#ifndef HTTPNIO_H_whVj9DjZzFKtzEUtC0Ma2Ae45Hm
#define HTTPNIO_H_whVj9DjZzFKtzEUtC0Ma2Ae45Hm

#include <netdb.h>
#include "selector.h"

#define SERVER_TIMEOUT 7
/**
 * httpproxynio -- el proxy propiamente dicho, maneja las conexiones
 * 		llama a los parsers y hace el pasaje de mensajes
 */

/** handler del socket pasivo que atiende conexiones http proxy */
void
socksv5_passive_accept(struct selector_key *key);


/** libera pools internos */
void
socksv5_pool_destroy(void);

#endif
