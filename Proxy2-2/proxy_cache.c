// =================================================================
// File Name    : proxy_cache.c
// Date         : 2025/05/08
// OS           : Ubuntu 22.04 LTS 64bits
// Author       : Choe Hyeon Jin
// Student ID   : 2023202070
// -----------------------------------------------------------------
// Title        : System Programming proxy Assignment #2-2
// Description  : A proxy server program that accepts HTTP requests from clients, 
//							checks if the requested URL has been cached using a SHA1 hash,
//							and returns a HIT or MISS response.
//							Each client is handled in a child process created via fork().
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
#include <sys/file.h>
#include <signal.h>
#include <sys/mman.h>

#define PORT 39999
#define BUF_SIZE 2048

int* total_hit;
int* total_miss;
time_t startTime;
time_t endTime;
char log_path[300];

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
// Function     : sigHandler
// -----------------------------------------------------------------
// Input        : int signo - Signal number (e.g., SIGINT)
// Output       : void
// Purpose      : Handle SIGINT signal. When Ctrl+C is received, logs the
//                total execution time and number of HIT and MISS requests
//                to the log file and exits.
// =================================================================

void sigHandler(int signo) {
	time(&endTime); // save program end time

	chdir(log_path); // cd to ~/logfile
	FILE* fp = fopen("logfile.txt", "a");
	flock(fileno(fp), LOCK_EX);

	fprintf(fp, "[Terminated] run time: %ld sec. #request hit : %d, miss : %d\n",
		endTime - startTime, *total_hit, *total_miss);
	flock(fileno(fp), LOCK_UN);
	fclose(fp);
	exit(0);
}

// =================================================================
// Function     : main
// -----------------------------------------------------------------
// Input        : -
// Output       : int - 0 success
// Purpose      : Parsing the request to extract the URL,
//                    checking HIT/MISS based on SHA1 hash,
//						sending appropriate HTTP response.
// =================================================================

int main() {
	time(&startTime); // save program start time

	// get home dir path
	char home[256];
	getHomeDir(home);

	// open logfile
	sprintf(log_path, "%s/logfile", home); // ~/logfile
	mkdir(log_path, 0777); // create log dir

	// allocate shared memory using mmap
	total_hit = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	total_miss = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	// initialize hit and miss counters to 0
	*total_hit = 0;
	*total_miss = 0;

	signal(SIGINT, sigHandler); // register SIGINT handler to handle ctrl+c termination
	
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

		printf("[%s : %d] client was connected\n", inet_ntoa(client.sin_addr), ntohs(client.sin_port));

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

			// print request
			puts("================================================");
			printf("Request from [%s : %d]\n", inet_ntoa(client.sin_addr), ntohs(client.sin_port));
			printf("%s", buf);
			puts("================================================");

			int isURL = 1;
			// parse request
			strcpy(tmp, buf);
			tok = strtok(tmp, " "); // extract method
			if (!tok || strcmp(tok, "GET") != 0) isURL = 0;
			tok = strtok(NULL, " "); // extract url
			if (!tok) isURL = 0;
			strcpy(url, tok);
			if (strstr(url, ".html") || strstr(url, ".ico") || strstr(url, ".css") || strstr(url, ".txt")) isURL = 0;

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
			if (isURL) mkdir(cache_dirname, 0777); // create cache subdir

			char cache_filename[38]; // remaining 37 chars
			strncpy(cache_filename, hashed_url + 3, 37);
			cache_filename[37] = '\0';

			// check hit or miss
			int hitFlag = 0;
			if (isURL) {
				struct dirent* pFile;
				DIR* pDir = opendir(cache_dirname);
				for (pFile = readdir(pDir); pFile; pFile = readdir(pDir)) {
					if (strcmp(pFile->d_name, cache_filename) == 0) { // hit
						hitFlag = 1;
						break;
					}
				}
				closedir(pDir);
			}
			
			char response_header[BUF_SIZE] = { 0, };
			char response_data[2 * BUF_SIZE] = { 0, };

			// open log file
			chdir(log_path); // cd to ~/logfile
			FILE* fp = fopen("logfile.txt", "a");
			flock(fileno(fp), LOCK_EX);

			// miss
			if (!hitFlag && isURL) {
				(*total_miss)++;
				// create response data
				sprintf(response_data,
					"<h1>MISS</h1><br>"
					"%s: %d<br>"
					"%s<br>"
					"kw2023202070", inet_ntoa(client.sin_addr), ntohs(client.sin_port), url);

				// write miss log
				fprintf(fp, "[Miss]%s-[%02d/%02d/%02d, %02d:%02d:%02d]\n",
					url, lt->tm_year + 1900, lt->tm_mon + 1,
					lt->tm_mday, lt->tm_hour, lt->tm_min, lt->tm_sec);
				flock(fileno(fp), LOCK_UN);
				fclose(fp);

				// create cache file
				chdir(dir_path); // cd to ~/cache/xxx
				creat(cache_filename, 0777);
			}

			// hit
			else if (hitFlag && isURL) {
				(*total_hit)++;
				// create response data
				sprintf(response_data,
					"<h1>HIT</h1><br>"
					"%s: %d<br>"
					"%s<br>"
					"kw2023202070", inet_ntoa(client.sin_addr), ntohs(client.sin_port), url);

				// write hit log
				fprintf(fp, "[Hit]%s/%s-[%02d/%02d/%02d, %02d:%02d:%02d]\n",
					cache_dirname, cache_filename, lt->tm_year + 1900,
					lt->tm_mon + 1, lt->tm_mday, lt->tm_hour, lt->tm_min, lt->tm_sec);
				fprintf(fp, "[Hit]%s\n", url);
				flock(fileno(fp), LOCK_UN);
				fclose(fp);
			}
			// create response header
			sprintf(response_header, "HTTP/1.0 200 OK\r\n"
				"Server:simple proxy server\r\n"
				"Content-length:%lu\r\n"
				"Content-type:text/html\r\n\r\n", strlen(response_data));

			// write(send) response message to client(web browser)
			write(cd, response_header, strlen(response_header));
			write(cd, response_data, strlen(response_data));

			printf("[%s : %d] client was disconnected\n", inet_ntoa(client.sin_addr), ntohs(client.sin_port));
			close(cd); // close client socket
			exit(0);
		}
		else { // parent process
			close(cd); // parent doesn¡¯t need client socket, child handles it
			int status;
			while (waitpid(-1, &status, WNOHANG) > 0); // reap zombie children
		}
	}
	close(sd); // close server socket
	return 0;
}