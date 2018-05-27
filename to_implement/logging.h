#ifndef LOGGER_H
#define LOGGER_H

#define DEV_LOG "dev.log"
#define PROD_LOG "prod.log"

/**
* Used for debugging and execution following.
* Use for de debugging on development.
* Use only on main functions for control on production.
*/
void LOG_DEBUG(char *);

/**
* Used for registering errors.
*/
void LOG_ERROR(char *);

/**
* Used for registering important messages.
* Eg: Start of execution, start of tests, exiting, sigterm, etc.
*/
void LOG_PRIORITY(char *str);
#endif
