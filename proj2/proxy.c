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

	port = strdup(argv[1]);
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

	/* Listening socket is properly created.
	 * Now listen incoming request on this socket */
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
		/* There is a new connection request. Accept that requst */
		new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
		if(new_fd == -1) {
			perror("accept");
			continue;
		}

		inet_ntop(their_addr.ss_family, get_addr((struct sockaddr *)&their_addr), s, sizeof(s));

		/* There is a new connection from client.
		 * Handle this request from child process */
		child_pid = fork();
		if(child_pid == 0) {
			char *message;

			/* Information in request line */
			char *request_method, *server_addr, *http_version, *save_ptr;
			/* To forward request to remote server, we need to convert client request
			 * to proper format, becuase of proxy server */
			char *forward_request, *forward_url;
			/* Header line is saved and concatenated in this variable */
			char *header = NULL;
			/* Check whether the request line is valid */
			bool is_valid_request;
			/* Check whether there is a Host header line */
			bool is_host_header_exist = false;

			/* Child process doesn't need waiting socket */
			close(sockfd);

			/* Read data until there is a line with \r\n */
			while(1) {
				char *cur_token;

				is_valid_request = false;

				/* Receive data from client */
				numbytes = recv(new_fd, buf, BUF_SIZE, 0);

				/* buf doesn't receive valid string */
				if(numbytes == -1) {
					perror("recv");
					exit(EXIT_FAILURE);
				}
				/* There is no more string to be read in the socket */
				else if(numbytes == 0) {
					break;
				}

				message = strdup(buf);
				cur_token = strtok_r(buf, " ", &save_ptr);
				if(strcmp(cur_token, "GET") == 0) {
					/* Current line is a request line */
					request_method = strdup(cur_token);
					cur_token = strtok_r(NULL, " ", &save_ptr);
					if(strncmp(cur_token, "http://", 7) == 0) {
						/* This is valid remote server name */
						server_addr = strdup(cur_token);
						cur_token = strtok_r(NULL, "\n", &save_ptr);
						if(strncmp(cur_token, "HTTP/1.0", 8) == 0) {
							/* This is valid HTTP version */
							http_version = strdup("HTTP/1.0\r\n");
							is_valid_request = true;
						}
					}
				}
				else if(strcmp(cur_token, "Host:") == 0) {
					/* Save hostname */
					cur_token = strtok_r(NULL, "\r", &save_ptr);
					hostname = strdup(cur_token);
					is_host_header_exist = true;
				}

				if(is_valid_request) {
					/* Request line is valid. Now make request line for forwarding */

					/* Request line from client contains full domain name.
					 * We need to convert this portion to contain only path portion.
					 * Until path delimeter, there are 2 '/' in the domain name */
					forward_url = strchr(server_addr, '/');
					for(int i = 0; i < 2; i++)
						forward_url = strchr(forward_url + 1, '/');

					/* Make new request line for forwarding */
					forward_request = malloc((strlen(request_method) + strlen(forward_url)
								+ strlen(http_version) + 1) * sizeof(char));
					strcpy(forward_request, request_method);
					strcat(forward_request, " ");
					strcat(forward_request, forward_url);
					strcat(forward_request, " ");
					strcat(forward_request, http_version);

					if(strcmp(save_ptr, "\0") != 0) {
						/* There are more data in the buf.
						 * buf data is probably come from tester code */
						char *host_token, *host_save;

						/* Find Host header line in the remaining message */
						host_token = strdup(save_ptr);
						host_token = strtok_r(host_token, "\r", &host_save);
						while(host_token != '\0') {
							if(strncmp(host_token, "Host:", 5) == 0) {
								host_token += 6;
								hostname = strdup(host_token);
								printf("hostname: %s\n", hostname);
								is_host_header_exist = true;
								break;
							}
							else {
								host_save += 1;
								host_token = strtok_r(NULL, "\r", &host_save);
							}
						}
						
						if(is_host_header_exist) {
							/* Now save_ptr point to Header list. Just forward this */
							forward_to_remote(forward_request, save_ptr, new_fd);
						}
						else {
							/* There is no Host header line. 
							 * Send error message to client */
							char *bad_request;

							bad_request = strdup("HTTP/1.0 400 Bad Request\r\n");
							if(send(new_fd, bad_request, strlen(bad_request), 0) < 0) {
								perror("send - bad request");
								exit(EXIT_FAILURE);
							}
						}
						break;
					}
				}
				else {
					/* We encounter first header line.
					 * Make space for this header line, and copy */
					if(header == NULL) {
						header = malloc(BUF_SIZE * sizeof(char));
						strcpy(header, message);
					}
					/* There are already header line.
					 * We just concatenate new header line to the header variable */
					else {
						strcat(header, message);
					}

					if(strcmp(buf, "\r\n") == 0 || strcmp(buf, "\n") == 0) {
						/* All header lines were received. */
						if(is_host_header_exist) {
							 /* Now send to remote server */
							forward_to_remote(forward_request, header, new_fd);
						}
						else {
							/* There is no Host header line. 
							 * Send error message to client */
							char *bad_request;

							bad_request = strdup("HTTP/1.0 400 Bad Request\r\n");
							if(send(new_fd, bad_request, strlen(bad_request), 0) < 0) {
								perror("send - bad request");
								exit(EXIT_FAILURE);
							}
						}
						break;
					}
				}
				bzero(buf, BUF_SIZE);
			}
			close(new_fd);
			exit(EXIT_SUCCESS);
		}
		/* Wait until previously created child process is finished */
		wait(NULL);
		close(new_fd);
	}

}

void forward_to_remote(char *forward_request, char *header, int client_sockfd)
{
	/* These variables are related to sending socket,
	   which sends data to remote server */
	int remote_sockfd, remote_rv, remote_numbytes;
	char remote_s[INET6_ADDRSTRLEN], remote_buf[BUF_SIZE];
	struct addrinfo remote_hints, *remote_res, *remote_p;

	/* Sending socket setting */
	memset(&remote_hints, 0, sizeof(remote_hints));
	remote_hints.ai_family = AF_INET;
	remote_hints.ai_socktype = SOCK_STREAM;

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
	freeaddrinfo(remote_res);

	/* Send data to the remote server */
	if(send(remote_sockfd, forward_request, strlen(forward_request), 0) < 0) {
		perror("remote: send");
		return;
	}
	if(send(remote_sockfd, header, strlen(header), 0) < 0) {
		perror("remote: send");
		return;
	}

	/* Receive data from remote server*/
	while((remote_numbytes = recv(remote_sockfd, remote_buf, BUF_SIZE, 0)) > 0) {
		send(client_sockfd, remote_buf, remote_numbytes, 0);
	}
	close(remote_sockfd);
}
