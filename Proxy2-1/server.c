// =================================================================
// File Name    : server.c
// Date         : 2025/05/01
// OS           : Ubuntu 22.04 LTS 64bits
// Author       : Choe Hyeon Jin
// Student ID   : 2023202070
// -----------------------------------------------------------------
// Title        : System Programming proxy Assignment #2-1
// Description  : A server program that handles clients 
//							creating sub process, cache file and log
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

#define PORT 1234
#define BUF_SIZE 1024

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
// Function     : main
// -----------------------------------------------------------------
// Input        : -
// Output       : int - 0 success
// Purpose      : receiving url from client, creating cache file 
//                     based on SHA1 hash, writing hit/miss and run time log
// =================================================================

int main() {
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
	server.sin_addr.s_addr = inet_addr("127.0.0.1");

	bind(sd, (struct sockaddr*)&server, sizeof(server)); // bind socket 
	listen(sd, 5); // wait for clients

	while (1) {
		cd = accept(sd, (struct sockaddr*)&client, &client_len); // accept connection with client
		if (cd < 0) continue;

		printf("[%s : %d] client was connected\n", inet_ntoa(client.sin_addr), ntohs(client.sin_port));

		pid_t pid = fork(); // create child process
		if (pid == 0) { // child process
			close(sd); // close server socket

			time_t childStartTime;
			time(&childStartTime); // save child start time

			// hit, miss count
			int hit = 0;
			int miss = 0;

			while (1) {
				// receive(read) input url from client
				char buf[BUF_SIZE] = { 0 };
				int buf_len = read(cd, buf, BUF_SIZE);
				buf[strcspn(buf, "\n")] = 0; // remove newline

				// get current time;
				time_t t;
				time(&t);
				struct tm* lt = localtime(&t);

				// open log file
				chdir(log_path); // cd to ~/logfile
				FILE* fp = fopen("logfile.txt", "a");

				// if input "bye"
				if (strcmp(buf, "bye") == 0) {
					time_t childEndTime;
					time(&childEndTime); // save child end time
					int runTime = childEndTime - childStartTime; // calc run time
					fprintf(fp, "[Terminated] ServerPID : %d | run time : %dsec. #request hit : %d, miss : %d\n",
						getpid(), runTime, hit, miss); // write terminate log

					fclose(fp); // close log file
					close(cd); // close client socket

					printf("[%s : %d] client was disconnected\n", inet_ntoa(client.sin_addr), ntohs(client.sin_port));
					exit(0);
				}
				// create cache dir
				char root_path[300];
				sprintf(root_path, "%s/cache", home); // ~/cache
				umask(0); // set umask 0
				mkdir(root_path, 0777); // create cache dir

				char hashed_url[41]; // hashed buffer
				sha1_hash(buf, hashed_url); // get SHA1 hash URL

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
				DIR* pDir;
				pDir = opendir(cache_dirname);
				for (pFile = readdir(pDir); pFile; pFile = readdir(pDir)) {
					if (strcmp(pFile->d_name, cache_filename) == 0) { // hit
						hitFlag = 1;
						break;
					}
				}
				closedir(pDir);

				if (!hitFlag) { // miss
					miss++; // count miss
					write(cd, "MISS", 5); // send(write) MISS result to server

					chdir(dir_path); // cd to ~/cache/xxx
					creat(cache_filename, 0777); // create cache file

					chdir(log_path); // cd to ~/logfile
					if (fp != NULL) { // write miss log
						fprintf(fp, "[MISS] ServerPID : %d | %s - [%04d/%02d/%02d, %02d:%02d:%02d]\n",
							getpid(), buf,
							lt->tm_year + 1900, lt->tm_mon + 1, lt->tm_mday,
							lt->tm_hour, lt->tm_min, lt->tm_sec);
						fflush(fp); // flush immediately
					}
				}
				else { // hit
					hit++; // count hit
					write(cd, "HIT", 4); // send(write) HIT result to server

					if (fp != NULL) { // write hit log
						fprintf(fp, "[HIT] ServerPID : %d | %s/%s - [%04d/%02d/%02d, %02d:%02d:%02d]\n",
							getpid(), cache_dirname, cache_filename,
							lt->tm_year + 1900, lt->tm_mon + 1, lt->tm_mday,
							lt->tm_hour, lt->tm_min, lt->tm_sec);
						fflush(fp);
						fprintf(fp, "[HIT] %s\n", buf);
						fflush(fp);
					}
				}
			}
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