#include "dispatch.h"
#include <stdlib.h>
#include <assert.h>

Dispatch_T* new_dispatch()
{
    Dispatch_T *dispatch = malloc(sizeof(Dispatch_T));
    assert(dispatch != NULL);

    dispatch->placeholder = 0;

    return dispatch;
}

void free_dispatch(Dispatch_T **dispatch)
{
    free(*dispatch);
    *dispatch = NULL;
}

int read_client_request(int fd, Dispatch_T *dispatch)
{
    return -1;
}