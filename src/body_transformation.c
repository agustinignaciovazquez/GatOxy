#include "body_transformation.h"


int
process_with_external_program(char * prog, int pipeToChild[2], int pipeToParent[2]) {
    int pid;

    if(pipe(pipeToChild) < 0 || pipe(pipeToParent) < 0) {
        return PIPE_FAIL;
    }


    pid = fork();

    if(pid > 0) {

        close(pipeToParent[WRITE]);
        pipeToParent[WRITE] = -1;
        close(pipeToChild[READ]);
        pipeToChild[READ] = -1;

    }
    else if(pid == 0) {
        dup2(pipeToChild[READ], STDIN_FILENO);
        dup2(pipeToParent[WRITE], STDOUT_FILENO);

        close(pipeToParent[READ]);
        close(pipeToChild[WRITE]);

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
