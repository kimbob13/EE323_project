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
#include "proxy.h"

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

	port = malloc(strlen(argv[1]) * sizeof(char));
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
		//printf("Waiting for connection...\n");
		sin_size = sizeof(their_addr);
		new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
		if(new_fd == -1) {
			perror("accept");
			continue;
		}

		inet_ntop(their_addr.ss_family, get_addr((struct sockaddr *)&their_addr), s, sizeof(s));

		child_pid = fork();
		if(child_pid == 0) {
			bool is_valid_request, is_success;
			char *message, *msg_token, *server_addr, *http_version;
			char *forward_request, *forward_url, *header_list[20] = {NULL};
			int header_index = 0;
			
			close(sockfd);
			while(1) {
				is_valid_request = false;
				is_success = false;

				numbytes = read(new_fd, buf, BUF_SIZE);
				if(numbytes == -1) {
					perror("read");
					exit(EXIT_FAILURE);
				}
				else if(numbytes == 0) {
					break;
				}
				
				/* Core part */
				message = malloc((BUF_SIZE + 1) * sizeof(char));
				strcpy(message, buf);
				msg_token = strtok(buf, " ");
				if(strcmp(message, "\r\n") == 0 || strcmp(message, "\n") == 0) {
					/* Empty line, next line is entity body */
					is_success = true;
				}
				else if(strcmp(msg_token, "GET") == 0) {
					server_addr = strtok(NULL, " ");
					if(strncmp(server_addr, "http://", 7) == 0) {
						http_version = strtok(NULL, " ");
						if(strncmp(http_version, "HTTP/1.0", 8) == 0) {
							is_valid_request = true;
						}
					}
				}
				else if(strchr(msg_token, ':') != NULL) {
					/* Header field */
					header_list[header_index] = malloc((strlen(message) + 1) * sizeof(char));
					strcpy(header_list[header_index], message);
					header_index++;
				}

				if(is_valid_request) {
					forward_request = malloc((strlen(message) + 1) * sizeof(char));

					/* Find server path that is to be forwarded.
					   Request message that is sent to proxy contains full host name.
					   So, when forward message to remote server,
					   we must remove that host address and send only path address */
					forward_url = strchr(server_addr, '/');
					for(int i = 0; i < 2; i++)
						forward_url = strchr(forward_url + 1, '/');

					/* Make forwarding request that will be sent to remote server */
					strcpy(forward_request, msg_token);
					strcat(forward_request, " ");
					strcat(forward_request, forward_url);
					strcat(forward_request, " ");
					strcat(forward_request, http_version);
				}
				else if(is_success) {
					/* Message from client is valid.
					   Now we have to send this message to remote server */
					forward_to_remote(forward_request, header_list, &new_fd);
					break;
				}
				bzero(buf, BUF_SIZE);
				free(message);
				/* Core part end */
			}
			close(new_fd);
			exit(EXIT_SUCCESS);
		}
		wait(NULL);
		close(new_fd);
	}

}

void forward_to_remote(char *forward_request, char *header_list[], int *client_sockfd)
{
	/* These variables are related to sending socket,
	   which sends data to remote server */
	int remote_sockfd, remote_rv, host_index;
	char remote_s[INET6_ADDRSTRLEN];
	struct addrinfo remote_hints, *remote_res, *remote_p;
	char *hostname, *host_p;

	/* Sending socket setting */
	memset(&remote_hints, 0, sizeof(remote_hints));
	remote_hints.ai_family = AF_INET;
	remote_hints.ai_socktype = SOCK_STREAM;

	/* Host name parsing */
	for(host_index = 0; header_list[host_index] != NULL; host_index++) {
		if(strncmp(header_list[host_index], "Host:", 5) == 0)
			break;
	}
	hostname = strtok(header_list[host_index], " ");
	hostname = strtok(NULL, " ");
	for(host_p = hostname; ; host_p++) {
		if(*host_p == '\r' || *host_p == '\n') {
			*host_p = '\0';
			break;
		}
	}

	/* Get address information of remote server, via http service */
	if((remote_rv = getaddrinfo(hostname, "http", &remote_hints, &remote_res)) != 0) {
		fprintf(stderr, "getaddrinfo - remote: %s\n", gai_strerror(remote_rv));
		return;
	}

	for(remote_p = remote_res; remote_p != NULL; remote_p = remote_p->ai_next) {
		if((remote_sockfd = socket(remote_p->ai_family, remote_p->ai_socktype, remote_p->ai_protocol)) == -1) {
			perror("remote: socket");
			continue;
		}

		if(connect(remote_sockfd, remote_p->ai_addr, remote_p->ai_addrlen) == -1) {
			close(remote_sockfd);
			perror("remote: connect");
			continue;
		}

		break;
	}

	if(remote_p == NULL) {
		fprintf(stderr, "remote: failed to connect\n");
		return;
	}

	inet_ntop(remote_p->ai_family, get_addr((struct sockaddr *)remote_p->ai_addr), remote_s, sizeof(remote_s));
	printf("proxy connected to remote server: %s\n", remote_s);

	freeaddrinfo(remote_res);

	/* These variables are related to receving socket,
	   which receives data from remote server */
	int recv_sockfd, recv_rv, new_recvfd, recv_child;
	char recv_s[INET6_ADDRSTRLEN], recv_buf[BUF_SIZE] = {0};
	struct addrinfo recv_hints, *recv_res, *recv_p;
	struct sockaddr_storage recv_their_addr;
	socklen_t recv_sin_size;
	struct sigaction recv_sa;
	int recv_yes = 1;
	int recv_numbytes;

	char *new_port = malloc(8 * sizeof(int) + 1);
	int new_port_num = atoi(port) + 1;
	itoa(new_port_num, new_port);

	/* Receiving socket setting */
	memset(&recv_hints, 0, sizeof(recv_hints));
	recv_hints.ai_family = AF_INET;
	recv_hints.ai_socktype = SOCK_STREAM;
	recv_hints.ai_flags = AI_PASSIVE;

	if((recv_rv = getaddrinfo(NULL, new_port, &recv_hints, &recv_res)) != 0) {
		fprintf(stderr, "getaddrinfo - recv_socket: %s\n", gai_strerror(recv_rv));
		return;
	}

	for(recv_p = recv_res; recv_p != NULL; recv_p = recv_p->ai_next) {
		if((recv_sockfd = socket(recv_p->ai_family, recv_p->ai_socktype, recv_p->ai_protocol)) == -1) {
			perror("recv_socket - socket");
			continue;
		}

		if(setsockopt(recv_sockfd, SOL_SOCKET, SO_REUSEADDR, &recv_yes, sizeof(int)) == -1) {
			perror("recv_sockfd - setsockopt");
			return;
		}

		if(bind(recv_sockfd, recv_p->ai_addr, recv_p->ai_addrlen) == -1) {
			close(recv_sockfd);
			perror("recv_sockfd - bind");
			continue;
		}

		break;
	}

	if(recv_p == NULL) {
		fprintf(stderr, "recv_sockfd: failed to bind\n");
		return;
	}

	freeaddrinfo(recv_res);

	recv_sa.sa_handler = sigchld_handler;
	sigemptyset(&recv_sa.sa_mask);
	recv_sa.sa_flags = SA_RESTART;
	if(sigaction(SIGCHLD, &recv_sa, NULL) == -1) {
		perror("recv_socket - sigaction");
		return;
	}

	/* Send data to the remote server */
	if(write(remote_sockfd, forward_request, strlen(forward_request)) < 0)
		perror("remote: write");
	for(int i = 0; header_list[i] != NULL; i++) {
		if(write(remote_sockfd, header_list[i], strlen(header_list[i])) < 0)
			perror("remote: write");
	}

	/* Receive data from remote server*/
	printf("Reading start\n");
	recv_sin_size = sizeof(recv_their_addr);
	new_recvfd = accept(recv_sockfd, (struct sockaddr *)&recv_their_addr, &recv_sin_size);
	inet_ntop(recv_their_addr.ss_family, get_addr((struct sockaddr *)&recv_their_addr), recv_s, sizeof(recv_s));

	recv_child = fork();
	if(recv_child == 0) {
		close(recv_sockfd);
		while(1) {
			recv_numbytes = read(new_recvfd, recv_buf, BUF_SIZE);
			if(recv_numbytes == -1) {
				perror("recv_sockfd - read");
				break;
			}
			else if(recv_numbytes == 0) {
				break;
			}

			if(write(*client_sockfd, recv_buf, BUF_SIZE) < 0) {
				perror("recv_sockfd - write");
				break;
			}
			bzero(recv_buf, BUF_SIZE);
		}

		close(new_recvfd);
		exit(EXIT_SUCCESS);
	}
	wait(NULL);
	close(recv_sockfd);
}

void itoa(int n, char s[])
{
	int i, sign;

	if((sign = n) < 0)
		n = -n;
	i = 0;
	do {
		s[i++] = n % 10 + '0';
	} while((n /= 10) > 0);

	if(sign < 0)
		s[i++] = '-';
	s[i] = '\0';
	reverse_string(s);
}

void reverse_string(char s[])
{
	int i, j;
	char c;

	for(i = 0, j = strlen(s) - 1; i < j; i++, j--) {
		c = s[i];
		s[i] = s[j];
		s[j] = c;
	}
}
