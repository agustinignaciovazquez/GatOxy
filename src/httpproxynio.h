#ifndef HTTPNIO_H_whVj9DjZzFKtzEUtC0Ma2Ae45Hm
#define HTTPNIO_H_whVj9DjZzFKtzEUtC0Ma2Ae45Hm

#include <netdb.h>
#include "selector.h"

/** handler del socket pasivo que atiende conexiones http proxy */
void
http_proxy_passive_accept(struct selector_key *key);


/** libera pools internos */
void
http_proxy_pool_destroy(void);

#endif
