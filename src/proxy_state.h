#include <stdlib.h>
#include <stdbool.h>

/** general proxy state */
typedef struct global_proxy_state {
    /** registers the amount of http bytes processed */
    unsigned                      initial;
    
    /** listening ports */
    unsigned port;
    unsigned confPort;

    /** logs */
    char dev_log[30];
    char prod_log[30];

    /** transformation enabled */
    bool do_transform;

    /** transformation command */
    char *transformation_command;

    /** transformation command */
    char *transformation_types;
} global_proxy_state;

/** create proxy state */
bool
proxy_state_create();

/** destroy proxy state */
void
proxy_state_destroy();