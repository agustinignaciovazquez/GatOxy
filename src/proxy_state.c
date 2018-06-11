#include "proxy_state.h"
#include <string.h>
/**
* The global state of the proxy at any time.
* should be accesible to all of the proxy using extern
*/
global_proxy_state *proxy_state;

bool
proxy_state_create() {

	proxy_state = malloc(sizeof(*proxy_state));

	proxy_state->bytesTransfered = 0;
	proxy_state->port = 1080;
	proxy_state->confPort = 1081;
	proxy_state->do_transform = false;
	proxy_state->transformation_command_index=0;
	strcpy(proxy_state->transformation_command, "sed -u -e 's/a/4/g' -e 's/e/3/g' -e 's/i/1/g' -e 's/o/0/g' -e's/s/5/g'");
	proxy_state->transformation_types_index=0;
	proxy_state->transformation_types[1]= '\0';

	return true;
}

void
proxy_state_destroy() {
	// free(proxy_state->transformation_command);
	// free(proxy_state->transformation_types);
 //    free(proxy_state);
}