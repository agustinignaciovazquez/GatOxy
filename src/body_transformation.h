#ifndef PC_2018_03_BODY_TRANSFORMATION_H
#define PC_2018_03_BODY_TRANSFORMATION_H

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

enum pipe_ends
{
    READ = 0, WRITE
};

enum errors_2
{
    PIPE_FAIL=2, FORK_FAIL, INVALID_PARAMETERS
};

/**
 * abre los pipes necesarios y procesa la transformacion
 */
int
process_with_external_program(char * prog, int pipeToChild[2], 
									int pipeToParent[2]);


#endif
