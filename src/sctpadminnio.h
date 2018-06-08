#ifndef SCTPNIO_H_whVj9DjZzFKtzEUtC0Ma2Ae45Hm
#define SCTPNIO_H_whVj9DjZzFKtzEUtC0Ma2Ae45Hm

#include <netdb.h>
#include "selector.h"

/** handler del socket pasivo que atiende conexiones sctp admin */
void
sctp_passive_accept(struct selector_key *key);


/** libera pools internos */
void
sctp_pool_destroy(void);


#endif
