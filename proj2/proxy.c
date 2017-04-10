#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BACKLOG 20
#define BUF_SIZE (1024 * 500)
#define UNUSED __attribute__ ((unused))

void sigchld_handler(int s UNUSED)
{
	while(waitpid(-1, NULL, WNOHANG) > 0);
}

void *get_addr(struct sockaddr *sa)
{
	if(sa->sa_family == AF_INET)
		return &(((struct sockaddr_in *)sa)->sin_addr);
	else
		return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

int main(int argc, char *argv[])
{
	int sockfd, new_fd;
	char *port = NULL;
	struct addrinfo hints, *res, *p;
	struct sockaddr_storage their_addr;
	socklen_t sin_size;
	struct sigaction sa;
	int yes = 1;
	char s[INET6_ADDRSTRLEN], buf[BUF_SIZE] = {0};
	int rv, child_pid, numbytes;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	if(argc != 2) {
		fprintf(stderr, "usage: %s -p <port number>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	strcpy(port, argv[1]);
	if(port == NULL) {
		fprintf(stderr, "Invalid port argument\n");
		exit(EXIT_FAILURE);
	}

	if((rv = getaddrinfo(NULL, port, &hints, &res)) != 0) {
		fprintf(stderr, "getaddrinfo - server: %s\n", gai_strerror(rv));
		return 1;
	}

	for(p = res; p != NULL; p = p->ai_next) {
		if((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
			perror("server: socket");
			continue;
		}

		if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
			perror("setsockopt");
			exit(EXIT_FAILURE);
		}

		if(bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("server: bind");
			continue;
		}

		break;
	}

	if(p == NULL) {
		fprintf(stderr, "server: failed to bind\n");
		return 2;
	}

	freeaddrinfo(res);

	if(listen(sockfd, BACKLOG) == -1) {
		perror("listen");
		exit(EXIT_FAILURE);
	}

	sa.sa_handler = sigchld_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if(sigaction(SIGCHLD, &sa, NULL) == -1) {
		perror("sigaction");
		exit(EXIT_FAILURE);
	}

	while(1) {
		sin_size = sizeof(their_addr);
		new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
		if(new_fd == -1) {
			perror("accept");
			continue;
		}

		inet_ntop(their_addr.ss_family, get_addr((struct sockaddr *)&their_addr), s, sizeof(s));

		child_pid = fork();
		if(child_pid == 0) {
			bool is_valid_request;
			
			close(sockfd);
			while(1) {
				char *msg_token;
				char *server_addr;
				char *http_version;

				is_valid_request = false;

				numbytes = read(new_fd, buf, BUF_SIZE);
				if(numbytes == -1) {
					perror("read");
					break;
				}
				else if(numbytes == 0)
					break;

				/* Core part */
				
				msg_token = strtok(buf, " ");
				if(strcmp(msg_token, "GET") == 0) {
					server_addr = strtok(NULL, " ");
					if(strncmp(server_addr, "http://", 7) == 0) {
						http_version = strtok(NULL, " ");
						if(strncmp(http_version, "HTTP/1.0", 8) == 0) {
							is_valid_request = true;
						}
					}
				}
				else if(msg_token[strlen(msg_token) - 2]  == ':') {
					/* Header field */
				}
				else if(strcmp(msg_token, "\r\n") == 0 || strcmp(msg_token, "\n") == 0) {
					/* Empty line, next line is entity data */
				}

				if(is_valid_request) {
					char *forward_request;
					char *forward_url;
					forward_request = malloc(strlen(buf) * sizeof(char));

					/* Find server path that is to be forwarded.
					   Request message that is sent to proxy contains full host name.
					   So, when forward message to remote server,
					   we must remove that host address and send only path address */
					for(int i = 0; i < 3; i++)
						forward_url = strchr(server_addr, '/');


					/* Copy request method */
					strcpy(forward_request, msg_token);
					/* Append space */
					strcat(forward_request, " ");
					/* Append request URL */
					strcat(forward_request, forward_url);
					/* Append space */
					strcat(forward_request, " ");
					/* Append HTTP version */
					strcat(forward_request, http_version);
					printf("Final forwarded request: %s\n", forward_request);

					continue;
				}
				else
					break;
				/* Core part end */
				bzero(buf, BUF_SIZE);
			}

			//if(!is_success)
				/* Some error code */
			close(new_fd);
		}
		wait(NULL);
		close(new_fd);
	}

}
