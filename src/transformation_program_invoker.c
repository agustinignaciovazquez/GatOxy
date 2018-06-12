/**
 * body_transformation.c -- realiza las transformaciones
 */
#include <stdio.h>
#include "transformation_program_invoker.h"

int
transformation_program_invoker(char * prog, int pipeToChild[2], 
									int pipeToParent[2], char *errFile) {

    int pid;
    if(pipe(pipeToChild) < 0 || pipe(pipeToParent) < 0) {
        return PIPE_FAIL;
    }
    pid = fork(); // TODO 
    if(pid > 0) {
        close(pipeToParent[WRITE]);
        pipeToParent[WRITE] = -1;
        close(pipeToChild[READ]);
        pipeToChild[READ] = -1;
    }else if(pid == 0) {
        close(pipeToParent[READ]);
    	close(pipeToChild[WRITE]);
    	if( dup2(pipeToChild[READ], STDIN_FILENO) == -1 ||
        		dup2(pipeToParent[WRITE], STDOUT_FILENO) == -1){
        	close(pipeToChild[READ]);
           	close(pipeToParent[WRITE]);
           	exit(1);
       	}

        freopen(errFile,"a" , stderr);

        system(prog);
        close(pipeToParent[WRITE]);
        pipeToParent[WRITE] = -1;
        exit(0);
    }
    else {
        return FORK_FAIL;
    }
    return 0;
}
