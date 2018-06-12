#include "proxy_state.h"

/**
 * El estado global del proxy en cualquier momento, deberia poderse acceder 
 * desde cualquier parte del proxy
 */
global_proxy_state *proxy_state;

bool
proxy_state_create() {

	proxy_state = malloc(sizeof(*proxy_state));
	proxy_state->bytesTransfered = 0;
	proxy_state->port = 1080;
	proxy_state->confPort = 1081;
	proxy_state->do_transform = false;
	proxy_state->transformation_command_index = 0;
	proxy_state->transformation_types_index = 0;
	proxy_state->transformation_command[1] = '\0';
	proxy_state->transformation_types[1] = '\0';

	return true;
}

void
proxy_state_destroy() {
	//TODO codear 

	// free(proxy_state->transformation_command);
	// free(proxy_state->transformation_types);
 	//    free(proxy_state);
}