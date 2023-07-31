/*
  Simple DirectMedia Layer
  Copyright (C) 1997-2023 Sam Lantinga <slouken@libsdl.org>

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.
*/
#include "SDL_internal.h"

/* TODO: Macro? */

#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

typedef enum
{
    ZENITY_MULTIPLE = 0x1,
    ZENITY_DIRECTORY = 0x2,
    ZENITY_SAVE = 0x4
} zenityFlags;

typedef struct
{
    SDL_DialogFileCallback callback;
    void* userdata;
    const char* filename;
    const SDL_DialogFileFilter *filters;
    Uint32 flags;
} zenityArgs;

/* TODO: Zenity survives termination of the parent */

static void run_zenity(zenityArgs* arg_struct)
{
    SDL_DialogFileCallback callback = arg_struct->callback;
    void* userdata = arg_struct->userdata;
    const char* filename = arg_struct->filename;
    const SDL_DialogFileFilter *filters = arg_struct->filters;
    Uint32 flags = arg_struct->flags;

    int out[2];
    pid_t process;
    const char *zenity_env = "/usr/bin/env";
    const char *zenity_arg0 = "zenity";
    const char *zenity_arg1 = "--file-selection";
    const char *zenity_arg2 = "--separator=\n";
    const char *zenity_arg_many = "--multiple";
    const char *zenity_arg_dir = "--directory";
    const char *zenity_arg_save = "--save";
    const char *zenity_arg_file_prefix = "--filename";
    const char *zenity_arg_filter_prefix = "--file-filter=";
    size_t bufferlen = SDL_strlen(zenity_env) + SDL_strlen(zenity_arg0) + SDL_strlen(zenity_arg1) + SDL_strlen(zenity_arg2) + 4 +
                       ((flags & ZENITY_MULTIPLE) ? SDL_strlen(zenity_arg_many) + 1 : 0) +
                       ((flags & ZENITY_DIRECTORY) ? SDL_strlen(zenity_arg_dir) + 1 : 0) +
                       ((flags & ZENITY_SAVE) ? SDL_strlen(zenity_arg_save) + 1 : 0) +
                       (filename ? SDL_strlen(zenity_arg_file_prefix) + SDL_strlen(filename) + 2 : 0);
    size_t nargs = 4 + !!(flags & ZENITY_MULTIPLE) + !!(flags & ZENITY_DIRECTORY) + !!(flags & ZENITY_SAVE) + (!!filename) * 2;

    const SDL_DialogFileFilter *filter_ptr = filters;
    char *buffer, *buffer_ptr;
    char **args, **args_ptr;
    int status = -1;

    if (filters) {
        while (filter_ptr->name && filter_ptr->pattern) {
            bufferlen += SDL_strlen(zenity_arg_filter_prefix) + SDL_strlen(filter_ptr->name) + SDL_strlen(filter_ptr->pattern) + 6; /* 3 bytes for ' | ', 2 bytes for the initial '*.', 1 terminating null byte */
            for (const char *c = filter_ptr->pattern; *c; c++) {
                if (*c == ';') {
                    bufferlen += 2; /* Prepend '*.' */
                }
            }
            nargs++;
            filter_ptr++;
        }
    }

    buffer = SDL_malloc(bufferlen);
    if (!buffer) {
        SDL_OutOfMemory();
        callback(NULL, userdata);
        return;
    }

    args = SDL_malloc((nargs + 1) * sizeof(char *));
    if (!args) {
        SDL_OutOfMemory();
        SDL_free(buffer);
        callback(NULL, userdata);
        return;
    }

    buffer_ptr = buffer;
    args_ptr = args;

    *args_ptr++ = buffer_ptr;
    SDL_strlcpy(buffer_ptr, zenity_env, bufferlen);
    buffer_ptr += SDL_strlen(zenity_env) + 1;

    *args_ptr++ = buffer_ptr;
    SDL_strlcpy(buffer_ptr, zenity_arg0, bufferlen);
    buffer_ptr += SDL_strlen(zenity_arg0) + 1;

    *args_ptr++ = buffer_ptr;
    SDL_strlcpy(buffer_ptr, zenity_arg1, bufferlen);
    buffer_ptr += SDL_strlen(zenity_arg1) + 1;

    *args_ptr++ = buffer_ptr;
    SDL_strlcpy(buffer_ptr, zenity_arg2, bufferlen);
    buffer_ptr += SDL_strlen(zenity_arg2) + 1;

    if (flags & ZENITY_MULTIPLE) {
        *args_ptr++ = buffer_ptr;
        SDL_strlcpy(buffer_ptr, zenity_arg_many, bufferlen);
        buffer_ptr += SDL_strlen(zenity_arg_many) + 1;
    }

    if (flags & ZENITY_DIRECTORY) {
        *args_ptr++ = buffer_ptr;
        SDL_strlcpy(buffer_ptr, zenity_arg_dir, bufferlen);
        buffer_ptr += SDL_strlen(zenity_arg_dir) + 1;
    }

    if (flags & ZENITY_SAVE) {
        *args_ptr++ = buffer_ptr;
        SDL_strlcpy(buffer_ptr, zenity_arg_save, bufferlen);
        buffer_ptr += SDL_strlen(zenity_arg_save) + 1;
    }

    if (filename) {
        *args_ptr++ = buffer_ptr;
        SDL_strlcpy(buffer_ptr, zenity_arg_file_prefix, bufferlen);
        buffer_ptr += SDL_strlen(zenity_arg_file_prefix) + 1;
        *args_ptr++ = buffer_ptr;
        SDL_strlcpy(buffer_ptr, filename, bufferlen);
        buffer_ptr += SDL_strlen(filename) + 1;
    }

    if (filters) {
        filter_ptr = filters;
        while (filter_ptr->name && filter_ptr->pattern) {
            *args_ptr++ = buffer_ptr;
            SDL_strlcpy(buffer_ptr, zenity_arg_filter_prefix, bufferlen);
            buffer_ptr += SDL_strlen(zenity_arg_filter_prefix);
            SDL_strlcpy(buffer_ptr, filter_ptr->name, bufferlen);
            buffer_ptr += SDL_strlen(filter_ptr->name);
            SDL_strlcpy(buffer_ptr, " | *.", bufferlen);
            buffer_ptr += 5;

            for (const char *c = filter_ptr->pattern; *c; c++) {
                if (*c == ';') {
                    *buffer_ptr++ = ' ';
                    *buffer_ptr++ = '*';
                    *buffer_ptr++ = '.';
                } else if (*c == '*' && (c[1] == '\0' || c[1] == ';')) {
                    *buffer_ptr++ = L'*';
                } else if (!((*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z') || (*c >= '0' && *c <= '9') || *c == '.' || *c == '_' || *c == '-')) {
                    SDL_SetError("Illegal character in pattern name: %c (Only alphanumeric characters, periods, underscores and hyphens allowed)", *c);
                    callback(NULL, userdata);
                    SDL_free(buffer);
                    SDL_free(args);
                    return;
                } else {
                    *buffer_ptr++ = *c;
                }
            }
            *buffer_ptr++ = '\0';

            filter_ptr++;
        }
    }

    *args_ptr++ = NULL;

    if (pipe(out) < 0) {
        SDL_SetError("Could not create pipe: %s", strerror(errno));
        SDL_free(buffer);
        SDL_free(args);
        callback(NULL, userdata);
        return;
    }

    process = fork();

    if (process < 0) {
        SDL_SetError("Could not fork process: %s", strerror(errno));
        SDL_free(buffer);
        SDL_free(args);
        close(out[0]);
        close(out[1]);
        callback(NULL, userdata);
        return;
    } else if (process == 0){
        dup2(out[1], STDOUT_FILENO);
        close(STDERR_FILENO); /* Hide errors from Zenity to stderr */
        close(out[0]);
        close(out[1]);
        /* Recent versions of Zenity have different exit codes, but picks up
          different codes from the environment */
        SDL_setenv("ZENITY_OK", "0", 1);
        SDL_setenv("ZENITY_CANCEL", "1", 1);
        SDL_setenv("ZENITY_ESC", "1", 1);
        SDL_setenv("ZENITY_EXTRA", "2", 1);
        SDL_setenv("ZENITY_ERROR", "2", 1);
        SDL_setenv("ZENITY_TIMEOUT", "2", 1);
        execv("/usr/bin/env", args);
        exit(errno + 128);
    } else {
        SDL_free(buffer);
        SDL_free(args);
        char readbuffer[2048];
        size_t bytes_read = 0, bytes_last_read;
        char *container = NULL;
        close(out[1]);

        while ((bytes_last_read = read(out[0], readbuffer, sizeof(readbuffer)))) {
            char *new_container = SDL_realloc(container, bytes_read + bytes_last_read);
            if (!new_container) {
                SDL_OutOfMemory();
                SDL_free(container);
                close(out[0]);
                callback(NULL, userdata);
                return;
            }
            container = new_container;
            SDL_memcpy(container + bytes_read, readbuffer, bytes_last_read);
            bytes_read += bytes_last_read;
        }
        close(out[0]);

        if (waitpid(process, &status, 0) == -1) {
            SDL_SetError("waitpid failed");
            SDL_free(container);
            callback(NULL, userdata);
            return;
        }

        if (WIFEXITED(status)) {
            status = WEXITSTATUS(status);
        }

        size_t narray = 1;
        char **array = (char **) SDL_malloc((narray + 1) * sizeof(char *));

        if (!array) {
            SDL_OutOfMemory();
            SDL_free(container);
            callback(NULL, userdata);
            return;
        }

        array[0] = container;
        array[1] = NULL;

        for (int i = 0; i < bytes_read; i++) {
            if (container[i] == '\n') {
                container[i] = '\0';
                /* Reading from a process often leaves a trailing \n, so ignore the last one */
                if (i < bytes_read - 1) {
                    array[narray] = container + i + 1;
                    narray++;
                    char **new_array = (char **) SDL_realloc(array, (narray + 1) * sizeof(char *));
                    if (!new_array) {
                        SDL_OutOfMemory();
                        SDL_free(container);
                        SDL_free(array);
                        callback(NULL, userdata);
                        return;
                    }
                    array = new_array;
                    array[narray] = NULL;
                }
            }
        }

        /* 0 = the user chose one or more files, 1 = the user canceled the dialog */
        if (status == 0 || status == 1) {
            callback((const char * const*) array, userdata);
        } else {
            SDL_SetError("Could not run zenity: exit code %d (may be zenity or execv+128)", status);
            callback(NULL, userdata);
        }

        SDL_free(array);
        SDL_free(container);
    }
}

static int run_zenity_thread(void* ptr)
{
    run_zenity(ptr);
    SDL_free(ptr);
    return 0;
}

/* TODO: Other methods (GTK, Qt, etc.) */

void SDL_ShowOpenFileDialog(SDL_DialogFileCallback callback, void* userdata, SDL_Window* window, const SDL_DialogFileFilter *filters, const char* default_location, int allow_many)
{
    zenityArgs *args;
    SDL_Thread *thread;

    args = SDL_malloc(sizeof(*args));
    if (!args) {
        SDL_OutOfMemory();
        callback(NULL, userdata);
        return;
    }

    args->callback = callback;
    args->userdata = userdata;
    args->filename = default_location;
    args->filters = filters;
    args->flags = allow_many ? ZENITY_MULTIPLE : 0;

    thread = SDL_CreateThread(run_zenity_thread, "SDL_ShowOpenFileDialog", (void *) args);

    if (thread == NULL) {
        callback(NULL, userdata);
        return;
    }

    SDL_DetachThread(thread);
}

void SDL_ShowSaveFileDialog(SDL_DialogFileCallback callback, void* userdata, SDL_Window* window, const SDL_DialogFileFilter *filters, const char* default_location)
{
    zenityArgs *args;
    SDL_Thread *thread;

    args = SDL_malloc(sizeof(zenityArgs));
    if (args == NULL) {
        SDL_OutOfMemory();
        callback(NULL, userdata);
        return;
    }

    args->callback = callback;
    args->userdata = userdata;
    args->filename = default_location;
    args->filters = filters;
    args->flags = ZENITY_SAVE;

    thread = SDL_CreateThread(run_zenity_thread, "SDL_ShowSaveFileDialog", (void *) args);

    if (thread == NULL) {
        callback(NULL, userdata);
        return;
    }

    SDL_DetachThread(thread);
}

void SDL_ShowOpenFolderDialog(SDL_DialogFileCallback callback, void* userdata, SDL_Window* window, const char* default_location, int allow_many)
{
    zenityArgs *args;
    SDL_Thread *thread;

    args = SDL_malloc(sizeof(zenityArgs));
    if (args == NULL) {
        SDL_OutOfMemory();
        callback(NULL, userdata);
        return;
    }

    args->callback = callback;
    args->userdata = userdata;
    args->filename = default_location;
    args->filters = NULL;
    args->flags = (allow_many ? ZENITY_MULTIPLE : 0) | ZENITY_DIRECTORY;

    thread = SDL_CreateThread(run_zenity_thread, "SDL_ShowOpenFolderDialog", (void *) args);

    if (thread == NULL) {
        callback(NULL, userdata);
        return;
    }

    SDL_DetachThread(thread);
}
