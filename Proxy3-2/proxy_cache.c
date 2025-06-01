// =================================================================
// File Name    : proxy_cache.c
// Date         : 2025/06/01
// OS           : Ubuntu 22.04 LTS 64bits
// Author       : Choe Hyeon Jin
// Student ID   : 2023202070
// -----------------------------------------------------------------
// Title        : System Programming proxy Assignment #3-2
// Description  : A proxy server that handles client HTTP requests,
//                caches responses, and logs activity using a semaphore.
//                In this assignment, threads are added to perform
//                asynchronous log writing within the critical section.
//                Each child process creates a thread to log HIT/MISS
//                events, and the parent process also creates a thread
//                when writing the termination log.
// =================================================================

#include <stdio.h> // sprintf()
#include <string.h> // strcpy()
#include <stdlib.h> // exit()
#include <openssl/sha.h> // SHA1()
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h> // getuid(), chdir()
#include <pwd.h> // getpwuid()
#include <sys/stat.h> // mkdir(), umask()
#include <fcntl.h> // creat()
#include <time.h>
#include <dirent.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <errno.h>
#include <netdb.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <pthread.h>

#define PORT 39999
#define ORIGIN_PORT 80
#define BUF_SIZE 2048

time_t startTime;
int child_count = 0;
pid_t parent_pid;
int semid;
struct LogThreadArgs {
	char message[BUF_SIZE * 2];
};

// =================================================================
// Function     : sha1_hash
// -----------------------------------------------------------------
// Input        : char* input_url - Source URL
//                char* hashed_url - Hashed URL converted to hexadecimal
// Output       : char* - hashed_url pointer that contains a hashed string
// Purpose      : Converting URLs into 40-digit hexadecimal strings using
//                SHA1 hash function
// =================================================================
char* sha1_hash(char* input_url, char* hashed_url) {
	unsigned char hashed_160bits[20];
	char hashed_hex[41];
	int i;

	SHA1(input_url, strlen(input_url), hashed_160bits);

	for (i = 0; i < sizeof(hashed_160bits); i++) {
		sprintf(hashed_hex + i * 2, "%02x", hashed_160bits[i]);
	}

	strcpy(hashed_url, hashed_hex);

	return hashed_url;
}

// =================================================================
// Function     : getHomeDir
// -----------------------------------------------------------------
// Input        : char* home - Buffer to store the home directory path
// Output       : char* - Home directory path pointer
// Purpose      : Returning the home directory path of the current user
// =================================================================
char* getHomeDir(char* home) {
	struct passwd* usr_info = getpwuid(getuid());
	strcpy(home, usr_info->pw_dir);

	return home;
}

// =================================================================
// Function     : getIPAddr
// -----------------------------------------------------------------
// Input        : char* addr - hostname (e.g., www.example.com)
// Output       : char* - dotted decimal IP address (e.g., 192.168.0.1)
// Purpose      : Convert hostname to IP address using gethostbyname()
// =================================================================
char* getIPAddr(char* addr) {
	struct hostent* hent;
	char* haddr;
	int len = strlen(addr);

	if ((hent = (struct hostent*)gethostbyname(addr)) != NULL) {
		haddr = inet_ntoa(*((struct in_addr*)hent->h_addr_list[0]));
	}
	return haddr;
}

// =================================================================
// Function     : init_semaphore
// -----------------------------------------------------------------
// Purpose      : initialize a System V semaphore set using semget()
//                with a key equal to the server port number
// =================================================================
void init_semaphore() {
	// initialize the system V semaphore using semget and semctl
	key_t semkey = (key_t)PORT; // semkey = PORT
	semid = semget(semkey, 1, IPC_CREAT | 0666);

	union semun {
		int val;
	} arg;
	arg.val = 1; 	// set initial value to 1
	semctl(semid, 0, SETVAL, arg); // apply the initial value using SETVAL
}

// =================================================================
// Function     : wait_semaphore
// -----------------------------------------------------------------
// Purpose      : perform P-operation (wait) on the semaphore to 
//                enter critical section (logfile access)
// =================================================================
void wait_semaphore() {
	struct sembuf p = { 0, -1, SEM_UNDO }; // define P-operation (wait) on semaphore
	semop(semid, &p, 1); // execute P-operation to enter critical section
}

// =================================================================
// Function     : post_semaphore
// -----------------------------------------------------------------
// Purpose      : perform V-operation (post) on the semaphore to 
//                exit critical section and allow others to enter
// =================================================================
void post_semaphore() {
	struct sembuf v = { 0, 1, SEM_UNDO }; // define V-operation (post) on semaphore
	semop(semid, &v, 1); // execute V-operation to leave critical section
}

// =================================================================
// Function     : remove_semaphore
// -----------------------------------------------------------------
// Purpose      : remove the semaphore set using semctl() when 
//                server terminates (called in sigint handler)
// =================================================================
void remove_semaphore() {
	semctl(semid, 0, IPC_RMID); // remove semaphore set when server terminates
}

// =================================================================
// Function     : log_thread
// -----------------------------------------------------------------
// Input        : void* arg - pointer to LogThreadArgs containing message
// Output       : void* - NULL on exit
// Purpose      : write log messages to logfile.txt
//                used for logging HIT/MISS/TERMINATION
//                asynchronously within a critical section.
// =================================================================
void* log_thread(void* arg) {
	struct LogThreadArgs* args = (struct LogThreadArgs*)arg;
	pthread_t tid = pthread_self();
	char home[256], log_path[300];
	getHomeDir(home);
	sprintf(log_path, "%s/logfile", home);
	chdir(log_path);

	FILE* fp = fopen("logfile.txt", "a");
	if (fp) {
		fprintf(fp, "%s", args->message);
		fclose(fp);
	}

	printf("*TID# %lu is exited.\n", tid);
	free(arg);
	pthread_exit(NULL);
}

// =================================================================
// Function : sig_int
// -----------------------------------------------------------------
// Input         : int signo - the signal number
// Output        : -
// Purpose       : Log server termination using SIGINT
// =================================================================
void sig_int(int signo) {
	if (getpid() != parent_pid) { // if child, exit
		exit(0);
	}
	time_t endTime;
	time(&endTime);
	int runTime = (int)(endTime - startTime); // calculate program run time

	wait_semaphore(); // enter critical section
	printf("*PID# %d is waiting for the semaphore.\n", getpid());
	printf("*PID# %d is in the critical zone.\n", getpid());

	// prepare termination log message and create thread
	struct LogThreadArgs* args = malloc(sizeof(struct LogThreadArgs));
	sprintf(args->message, "**SERVER** [Terminated] run time: %d sec. #sub process: %d\n", runTime, child_count);
	pthread_t tid;
	pthread_create(&tid, NULL, log_thread, args);
	printf("*PID# %d create the *TID# %lu.\n", getpid(), tid);
	pthread_join(tid, NULL); // wait for thread to finish

	printf("*PID# %d exited the critical zone.\n", getpid());
	post_semaphore(); // exit critical section

	remove_semaphore();
	exit(0);
}

// =================================================================
// Function     : signalHandlers
// -----------------------------------------------------------------
// Purpose      : Setup signal handlers for SIGINT
// =================================================================
void signalHandler() {
	if (signal(SIGINT, sig_int) == SIG_ERR) {
		exit(1);
	}
}

// =================================================================
// Function     : main
// -----------------------------------------------------------------
// Input        : -
// Output       : int - 0 success
// Purpose      : Initialize the proxy server and handles HTTP requests.
//                Accept client connections, fork child processes to
//                handle each request, and determine cache HIT or MISS.
//                - HIT: Send cached response, log with thread
//                - MISS: Request from origin server, cache response,
//                        log with thread
//                - All logging is performed inside a critical section
//                  protected by a semaphore.
//                - Each log entry is handled by a separate thread.
//                - On SIGINT, the parent logs termination info via thread.
// =================================================================
int main() {
	time(&startTime);
	signalHandler();
	init_semaphore(); // initialize semaphore
	parent_pid = getpid(); // save parent process id

	// get home dir path
	char home[256];
	getHomeDir(home);

	// open logfile
	char log_path[300];
	sprintf(log_path, "%s/logfile", home); // ~/logfile
	mkdir(log_path, 0777); // create log dir

	struct sockaddr_in server, client; // socket address struct
	int client_len = sizeof(client); // client's socket address size
	int sd, cd; // server, client socket descriptor
	sd = socket(AF_INET, SOCK_STREAM, 0); // create socket
	
	// server's socket address initialization
	memset((char*)& server, '\0', sizeof(server));
	server.sin_family = AF_INET;
	server.sin_port = htons(PORT);
	server.sin_addr.s_addr = htonl(INADDR_ANY);

	bind(sd, (struct sockaddr*)&server, sizeof(server)); // bind socket 
	listen(sd, 5); // wait for clients

	while (1) {
		cd = accept(sd, (struct sockaddr*)&client, &client_len); // accept connection with client
		if (cd < 0) continue;

		pid_t pid = fork(); // create child process
		if (pid == 0) { // child process
			time_t childStartTime;
			time(&childStartTime); // save child start time
			close(sd); // close server socket

			char buf[BUF_SIZE] = { 0, };
			char tmp[BUF_SIZE] = { 0, };
			char url[BUF_SIZE] = { 0, };
			char* tok = NULL;
			read(cd, buf, BUF_SIZE); // // read(receive) HTTP request from client(web browser)

			// get current time
			time_t t;
			time(&t);
			struct tm* lt = localtime(&t);

			int isURL = 1;
			// parse request
			strcpy(tmp, buf);
			tok = strtok(tmp, " "); // extract method
			if (!tok || strcmp(tok, "GET") != 0) isURL = 0;
			tok = strtok(NULL, " "); // extract url
			if (!tok) isURL = 0;
			strcpy(url, tok);
			if (strstr(url, ".ico") || strstr(url, ".css") || strstr(url, ".txt") || strstr(url, "firefox")) isURL = 0;

			char hashed_url[41]; // hashed buffer
			sha1_hash(url, hashed_url); // get SHA1 hash URL

			// create cache dir
			char root_path[300];
			sprintf(root_path, "%s/cache", home); // ~/cache
			umask(0); // set umask 0
			mkdir(root_path, 0777);

			char cache_dirname[4]; // first 3 chars
			strncpy(cache_dirname, hashed_url, 3);
			cache_dirname[3] = '\0';

			char dir_path[304];
			sprintf(dir_path, "%s/%s", root_path, cache_dirname); // ~/cache/xxx

			chdir(root_path); // cd to ~/cache 
			mkdir(cache_dirname, 0777); // create cache subdir

			char cache_filename[38]; // remaining 37 chars
			strncpy(cache_filename, hashed_url + 3, 37);
			cache_filename[37] = '\0';

			// check hit or miss
			int hitFlag = 0;
			struct dirent* pFile;
			DIR* pDir = opendir(cache_dirname);
			for (pFile = readdir(pDir); pFile; pFile = readdir(pDir)) {
				if (strcmp(pFile->d_name, cache_filename) == 0) { // hit
					hitFlag = 1;
					break;
				}
			}
			closedir(pDir);

			// hit
			if (hitFlag) {
				// write hit log only input url
				if (isURL) {
					wait_semaphore(); // wait (P-operation) to enter the critical section for log
					printf("*PID# %d is waiting for the semaphore.\n", getpid());
					printf("*PID# %d is in the critical zone.\n", getpid());

					// prepare log message and create thread
					struct LogThreadArgs* args = malloc(sizeof(struct LogThreadArgs));
					sprintf(args->message, "[HIT]%s/%s-[%04d/%02d/%02d, %02d:%02d:%02d]\n[HIT] %s\n",
						cache_dirname, cache_filename, lt->tm_year + 1900,
						lt->tm_mon + 1, lt->tm_mday, lt->tm_hour, lt->tm_min, lt->tm_sec, url);

					pthread_t tid;
					pthread_create(&tid, NULL, log_thread, args);
					printf("*PID# %d create the *TID# %lu.\n", getpid(), tid);
					pthread_join(tid, NULL); // wait for thread to finish

					printf("*PID# %d exited the critical zone.\n", getpid());
					post_semaphore(); // post (V-operation) to exit the critical section after log
				}

				// open cache file and send response to client(web browser)
				chdir(dir_path);
				FILE* cache = fopen(cache_filename, "r");
				char filedata[BUF_SIZE * 10] = { 0 };
				size_t cache_len = fread(filedata, sizeof(char), sizeof(filedata), cache);
				fclose(cache);
				write(cd, filedata, cache_len);
			}

			// miss
			else if (!hitFlag) {
				// write miss log only input url
				if (isURL) {
					wait_semaphore(); // wait (P-operation) to enter the critical section for log
					printf("*PID# %d is waiting for the semaphore.\n", getpid());
					printf("*PID# %d is in the critical zone.\n", getpid());

					// prepare log message and create thread
					struct LogThreadArgs* args = malloc(sizeof(struct LogThreadArgs));
					sprintf(args->message, "[MISS]%s-[%04d/%02d/%02d, %02d:%02d:%02d]\n",
						url, lt->tm_year + 1900, lt->tm_mon + 1, lt->tm_mday,
						lt->tm_hour, lt->tm_min, lt->tm_sec);

					pthread_t tid;
					pthread_create(&tid, NULL, log_thread, args);
					printf("*PID# %d create the *TID# %lu.\n", getpid(), tid);
					pthread_join(tid, NULL); // wait for thread to finish

					printf("*PID# %d exited the critical zone.\n", getpid());
					post_semaphore(); // post (V-operation) to exit the critical section after log
				}

				// GET http://example.com:8080/index.html HTTP/1.1
				// extract hostname, port, path from buf(browser request)
				char method[16], uri[1024], http_version[32];
				char parsed_hostname[256] = { 0 }, parsed_port[8] = "80", parsed_path[1024] = "/";
				sscanf(buf, "%s %s %s", method, uri, http_version); // extract GET, http://..., HTTP/1.1 from buf

				// http://hostname[:port]/path
				if (strncmp(uri, "http://", 7) == 0) {
					char* host_begin = uri + 7; // next to "http://"
					char* path_begin = strchr(host_begin, '/'); // divide by "/"

					if (path_begin) {
						strncpy(parsed_path, path_begin, sizeof(parsed_path) - 1);
						*path_begin = '\0'; // hostname:port
					}

					// if port exists split host:port
					char* colon = strchr(host_begin, ':');
					if (colon) {
						*colon = '\0';
						strncpy(parsed_hostname, host_begin, sizeof(parsed_hostname) - 1);
						strncpy(parsed_port, colon + 1, sizeof(parsed_port) - 1);
					}
					else {
						strncpy(parsed_hostname, host_begin, sizeof(parsed_hostname) - 1);
					}
				}

				char* ip = getIPAddr(parsed_hostname); // get origin server ip from request hostname
				if (!ip) exit(1);

				int od; // origin server socket descriptor
				struct sockaddr_in origin; // socket address struct
				od = socket(AF_INET, SOCK_STREAM, 0); // create socket

				// server's socket address initialization
				memset((char*)&origin, '\0', sizeof(origin));
				origin.sin_family = AF_INET;
				origin.sin_port = htons(ORIGIN_PORT);
				inet_pton(AF_INET, ip, &origin.sin_addr);

				// connect(od, (struct sockaddr*)&origin, sizeof(origin)); // connect to origin server
				if (connect(od, (struct sockaddr*)&origin, sizeof(origin)) < 0) {
					printf("connect error, exit child\n");
					exit(1);
				}

				// create request line for origin server
				char fixed_request[BUF_SIZE * 2] = { 0 };
				sprintf(fixed_request, "%s %s HTTP/1.0\r\n", method, parsed_path);

				// extract request header lines below "Host" from buf
				char* header_start = strstr(buf, "\r\n");
				if (header_start) {
					strncat(fixed_request, header_start + 2, sizeof(fixed_request) - strlen(fixed_request) - 1);
				}

				// include required request headers
				if (!strstr(fixed_request, "Connection:")) {
					strcat(fixed_request, "Connection: close\r\n");
				}
				if (!strstr(fixed_request, "User-Agent:")) {
					strcat(fixed_request, "User-Agent: Mozilla/5.0\r\n");
				}
				strcat(fixed_request, "\r\n"); // end of request headers

				write(od, fixed_request, strlen(fixed_request));

				// receive HTTP response from origin server
				int total = 0;
				int len;
				char res_buf[BUF_SIZE * 10] = { 0 };
				while ((len = read(od, res_buf + total, BUF_SIZE * 4 - total)) > 0) {  
					total += len;
				}
				if (total == 0) {
					printf("========== no response received ==========\n");
				}
				write(cd, res_buf, total); // send HTTP response from origin server to web browser

				// create cache file
				chdir(dir_path); // cd to ~/cache/xxx
				FILE* cache = fopen(cache_filename, "w");
				chmod(cache_filename, 0777);
				fwrite(res_buf, sizeof(char), total, cache); // store HTTP response into cache file
				fclose(cache);

				close(od);
			}
			close(cd); // close client socket
			exit(0);
		}
		else { // parent process
			child_count++;
			while (waitpid(-1, NULL, WNOHANG) > 0);
			close(cd); // parent does not need client socket, child handles it
		}
	}
	close(sd); // close server socket
	return 0;
}