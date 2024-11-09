typedef struct {
    int placeholder;
} Dispatch_T;

Dispatch_T* new_dispatch();

void free_dispatch(Dispatch_T **dispatch);

int read_client_request(int fd, Dispatch_T *dispatch);