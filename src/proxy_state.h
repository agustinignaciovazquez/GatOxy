#include <stdlib.h>
#include <stdbool.h>

/** general proxy state */
typedef struct global_proxy_state {
    /** registers the amount of http bytes processed */
    unsigned                      bytesTransfered;
    
    /** listening ports */
    unsigned port;
    unsigned confPort;

    /** transformation enabled */
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
    char *http_interface;

    /** interfaz proxy */
    char *proxy_interface;




} global_proxy_state;

/** create proxy state */
bool
proxy_state_create(int argc, const char **argv);

/** destroy proxy state */
void
proxy_state_destroy();