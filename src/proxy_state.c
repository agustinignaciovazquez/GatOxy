#include "proxy_state.h"

/**
* The global state of the proxy at any time.
* should be accesible to all of the proxy using extern
*/
global_proxy_state *proxy_state;

bool
proxy_state_create() {

	proxy_state = malloc(sizeof(*proxy_state));



	proxy_state->initial = 0;
	proxy_state->port = 1080;
	proxy_state->confPort = 1081;
	proxy_state->do_transform = false;
	// proxy_state->transformation_command;
	// proxy_state->transformation_types;

	return true;
}

void
proxy_state_destroy() {
	// free(proxy_state->transformation_command);
	// free(proxy_state->transformation_types);
 //    free(proxy_state);
}