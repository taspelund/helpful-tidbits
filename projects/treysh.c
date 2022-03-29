#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#define TREYSH_RL_BUFSIZE 1024                      /* max chars per line */
#define TREYSH_MAX_CMDS 64                          /* max comands per execution */
#define TREYSH_TOK_DELIM " \t\r\n\a"                /* token delimiters */
#define clear() fprintf(stdout, "\033[H\033[J")     /* ascii escape to clear term */
#define TREYSH_PERROR()                             /* err logging */                   \
        fprintf(stderr, "%s:%d(%s): %s\n", __FILE__, __LINE__, __func__, strerror(errno))

/* func prototypes for builtins */
int treysh_cd(char **args);
int treysh_clear(char **args);
int treysh_help(char **args);
int treysh_exit(char **args);

/* list of builtin name strings */
char *builtin_str[] = {
    "cd",
    "clear",
    "exit",
    "help"
};

/* list of func pointers to builtins */
int (*builtin_func[]) (char **) = {
    &treysh_cd,
    &treysh_clear,
    &treysh_exit,
    &treysh_help
};

int treysh_num_builtins() {
    return sizeof(builtin_str) / sizeof(char *);
}

int treysh_cd(char **args) {
    if (args[1] == NULL)
        fprintf(stderr, "treysh: expected argument to `cd`\n");
    else if (chdir(args[1]) != 0)
        TREYSH_PERROR();
    return 1;
}

int treysh_clear(char **args) {
    clear();
    return 1;
}

int treysh_help(char **args) {
    fprintf(stdout, "Trey Aspelund's treysh\n");
    fprintf(stdout, "Enter program names (and arguments) and hit enter to execute.\n");
    fprintf(stdout, "The following are built into treysh:\n");

    for (int i = 0; i < treysh_num_builtins(); i++)
        fprintf(stdout, "  - %s\n", builtin_str[i]);

    fprintf(stdout, "Use the `man` command for info about other programs.\n");
    return 1;
}

int treysh_exit(char **args){
    return 0;
}

void treysh_welcome(void) {
    fprintf(stdout, "======================\n");
    fprintf(stdout, "| Welcome to treysh! |\n");
    fprintf(stdout, "======================\n");
    return;
}

void init_treysh(void) {
    /** TODO: add logic to parse .treyshrc file */
    treysh_welcome();
    return;
}

char *treysh_read_line(void) {
    int bufsize = TREYSH_RL_BUFSIZE;
    int position = 0;
    char *buffer;
    int c;

    buffer = malloc(sizeof(char) * bufsize);
    if (!buffer) {
        fprintf(stderr, "%s: malloc error!\n", __func__);
        exit(EXIT_FAILURE);
    }

    while (1) {
        c = getchar();
        /* if we get a newline, null-terminate and return
         * the string holding the line.
         */
        if (c == '\n') {
            buffer[position] = '\0';
            return buffer;
        } else if (c == EOF) {      /* if we get EOF (ctrl-d), bail out */
            fprintf(stdout, "%s: Received EOF, exiting shell.\n", __func__);
            exit(EXIT_SUCCESS);
        } else
            buffer[position] = c;
        position++;

        /* if we exceed the buffer, reallocate. */
        if (position >= bufsize) {
            bufsize += TREYSH_RL_BUFSIZE;
            buffer = realloc(buffer, bufsize);
            if (!buffer) {
                fprintf(stderr, "%s: realloc error!\n", __func__);
                exit(EXIT_FAILURE);
            }
        }
    }
}

char **treysh_split_line_by_delim(char *line, char *delim) {
    int num_delims = 0;
    char **cmd = NULL;
    char *p = strtok(line, delim);

    while (p) {
        cmd = realloc(cmd, sizeof(char*) * ++num_delims);
        if (cmd == NULL)
            exit(-1);   /* mem allocation failed */

        cmd[num_delims - 1] = p;
        p = strtok(NULL, delim);
    }

    cmd = realloc(cmd, sizeof(char*) * (num_delims + 1));
    cmd[num_delims] = NULL;

    return cmd;
}

void treysh_parse_line(char *line, char ***cmdlines) {
    char **cmds;    /* array of commands, 1 string = 1 command */
    int i = 0;
    
    cmds = treysh_split_line_by_delim(line, "|");
    for (i = 0; cmds[i] != NULL; i++)
        cmdlines[i] = treysh_split_line_by_delim(cmds[i], TREYSH_TOK_DELIM);
    cmdlines[i] = NULL;
}

int treysh_launch(char ***cmds) {
    pid_t pid;
    pid_t wpid;
    int pipefd_prev[2];
    int pipefd_next[2];
    int status, i;
    char **args;

    for (i = 0; cmds[i] != NULL; i++) {
        args = cmds[i];

        if (cmds[i+1] != NULL) {    /* if !last cmd */
            if (pipe(pipefd_next) == -1) {   /* pipe error */
                TREYSH_PERROR();
                exit(EXIT_FAILURE);
            }
        }

        pid = fork();

        if (pid == 0) {         /* child */
            if (&cmds[i] != cmds) {             /* if previous cmd exists */
                dup2(pipefd_prev[0], STDIN_FILENO);
                close(pipefd_prev[0]);
                close(pipefd_prev[1]);
            }
            if (cmds[i+1] != NULL) {            /* if next cmd exists */
                close(pipefd_next[0]);
                dup2(pipefd_next[1], STDOUT_FILENO);
                close(pipefd_next[1]);
            }
            if (execvp(args[0], args) == -1)    /* exec error */ 
                TREYSH_PERROR();
            exit(EXIT_FAILURE);
        } else if (pid < 0)     /* fork error */
            TREYSH_PERROR();
        else {                  /* parent */
            if (&cmds[i] != cmds) {             /* if previous cmd exists */
                close(pipefd_prev[0]);
                close(pipefd_prev[1]);
            }
            if (cmds[i+1] != NULL)              /* if next cmd exists */
                pipefd_prev[0] = pipefd_next[0];
                pipefd_prev[1] = pipefd_next[1];
            do
                wpid = waitpid(pid, &status, WUNTRACED);
            while (!WIFEXITED(status) && !WIFSIGNALED(status));
        }
    }

    return 1;
}

int treysh_execute(char ***cmds) {
    int i, j;

    if (cmds[0] == NULL)     /* an empty command was entered */
        return 1;
    
    for (i = 0; cmds[i] != NULL; i++) {     /* check for builtin */
        for (j = 0; j < treysh_num_builtins(); j++) {
            if (strcmp(cmds[i][0], builtin_str[j]) == 0)
                return (*builtin_func[j])(cmds[i]);
        }
    }

    return treysh_launch(cmds);
}

void treysh_loop(void) {
    char *line;         /* string of user input */
    char ***cmdlines;   /* array of cmds, each element is an array of arg strings */
    int status, i;
    
    cmdlines = malloc(sizeof(char**) * TREYSH_MAX_CMDS);

    do {
        fprintf(stdout, "\n--> "); /* prompt */
        line = treysh_read_line();
        treysh_parse_line(line, cmdlines);

        /* evaluate and execute tokens */
        status = treysh_execute(cmdlines);

        /* cleanup each arg array. we don't need a memory leak */
        for (i = 0; cmdlines[i] != NULL; i++)
            free(cmdlines[i]);
        free(line);

    } while (status);
}

int main(int argc, char **argv) {
    init_treysh();
    treysh_loop();
    return EXIT_SUCCESS;
}
