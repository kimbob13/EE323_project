#ifndef PROXY_H
#define PROXY_H

#define BACKLOG 20
#define BUF_SIZE (1024 * 1024)
#define UNUSED __attribute__ ((unused))

char *port = NULL;
char *hostname;

void forward_to_remote(char *forward_request, char *header, int client_sockfd);

#endif
