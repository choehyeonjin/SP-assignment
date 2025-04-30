// =================================================================
// File Name    : server.c
// Date         : 2025/04/
// OS           : Ubuntu 22.04 LTS 64bits
// Author       : Choe Hyeon Jin
// Student ID   : 2023202070
// -----------------------------------------------------------------
// Title        : System Programming proxy Assignment #2-1
// Description  : A program that converts the input URL into SHA1
//                and creates cache directory, file and miss/hit log
// =================================================================

#include <stdio.h> // sprintf()
#include <string.h> // strcpy()
#include <openssl/sha.h> // SHA1()
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h> // getuid(), chdir()
#include <pwd.h> // getpwuid()
#include <sys/stat.h> // mkdir(), umask()
#include <fcntl.h> // creat()
#include <time.h>
#include <dirent.h>
#include <arpa/inet.h>

#define PORT 8888

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

void process(int client_sock, char* input_url, FILE* fp, int* hit, int* miss) {
	char hashed_url[41]; // hashed buffer

	// get home dir path
	char home[256];
	getHomeDir(home);

	// create cache dir
	char root_path[300];
	sprintf(root_path, "%s/cache", home); // ~/cache
	umask(0); // set umask 0
	mkdir(root_path, 0777); // create cache dir

	// open logfile
	char log_path[300];
	sprintf(log_path, "%s/logfile", home); // ~/logfile
	mkdir(log_path, 0777); // create log dir
	chdir(log_path); // cd to ~/logfile
	FILE* fp = fopen("logfile.txt", "a"); // open log file

	// get current time;
	time_t t;
	time(&t);
	struct tm* lt = localtime(&t);

	sha1_hash(input_url, hashed_url); // get SHA1 hash URL

	char cache_dirname[4]; // first 3 chars
	strncpy(cache_dirname, hashed_url, 3);
	cache_dirname[3] = '\0';

	char dir_path[304];
	sprintf(dir_path, "%s/%s", root_path, cache_dirname); // ~/cache/xxx
	mkdir(dir_path, 0777); // create cache subdir

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
			hit++; // count hit
			hitFlag = 1;
			break;
		}
	}
	closedir(pDir);

	if (!hitFlag) { // miss
		chdir(dir_path); // cd to ~/cache/xxx
		creat(cache_filename, 0777); // create cache file
		miss++; // count miss
	}

	chdir(log_path); // cd to ~/logfile
	if (!hitFlag) { // miss
		if (fp != NULL) { // write miss log
			fprintf(fp, "[Miss]%s-[%04d/%02d/%02d, %02d:%02d:%02d]\n",
				input_url, lt->tm_year + 1900, lt->tm_mon + 1,
				lt->tm_mday, lt->tm_hour, lt->tm_min, lt->tm_sec);
		}
	}
	else { // hit
		dprintf(cd, "HIT\n");

		if (fp != NULL) { // write hit log
			fprintf(fp, "[HIT] ServerPID : %d | %s/%s-[%04d/%02d/%02d, %02d:%02d:%02d]\n",
				getpid(), cache_dirname, cache_filename,
				lt->tm_year + 1900, lt->tm_mon + 1, lt->tm_mday,
				lt->tm_hour, lt->tm_min, lt->tm_sec);
			fprintf(fp, "[HIT] %s\n", input_url);
		}
	}
}

// =================================================================
// Function     : main
// -----------------------------------------------------------------
// Input        : -
// Output       : int - 0 success
// Purpose      : Getting URL from user, creating cache file
//                based on SHA1 hash, writing hit/miss and run time log
// =================================================================

int main() {
	time_t startTime;
	time(&startTime); // save program start time

	struct sockaddr_in server, client; // socket address struct
	int client_len = sizeof(client); // client's socket address size
	int sd, cd; // server, client socket descriptor

	sd = socket(AF_INET, SOCK_STREAM, 0); // create server's socket
	
	// server's socket address initialization
	memset(char*)& server, '\0', sizeof(server));
	server.sin_family = AF_INET;
	server.sin_port = htos(PORT);
	server.sin_addr.s_addr = inet_addr("127.0.0.1");

	bind(sd, (struct sockaddr*)&server, sizeof(server));
	listen(sd, 5);

	while (1) {
		cd = accept(sd, (struct sockaddr*)&client_addr, &client_len);
		if (cd < 0) continue;

		printf("[%s : %d] client was connected\n", inet_ntoa(client.sin_addr), ntohs(client.sin_port));
	
		pid_t pid = fork(); // create sub process
		if (pid == 0) { // child
			close(sd);

			time_t childStartTime;
			time(&childStartTime); // save child start time

			int hit, miss = 0; // hit, miss count

			while (1) {
				char buf[1024] = { 0 };
				int buf_len = read(cd, buf, 1024);
				buf[strcspn(buf, "\n")] = 0;

				printf("input url> ");
				scanf("%s", input_url); // get input
				time_t t;
				time(&t); // get current time
				struct tm* lt = localtime(&t);

				if (strcmp(input_url, "bye") == 0) { // check if "bye"
					time_t childEndTime;
					time(&childEndTime); // save child end time
					int runTime = childEndTime - startTime; // calc run time
					fprintf(fp, "[Terminated] ServerPID : %d | run time : %dsec. #request hit : %d, miss : %d\n",
						getpid(), runTime, hit, miss); // write terminate log
					fclose(fp); // close log

					close(cd);
					printf("[%s : %d] client was disconnected\n", inet_ntoa(client.sin_addr), ntohs(client_addr.sin_port));
					exit(0);
				}
				process(cd, buf, fp, &hit, &miss);

				

				
				
			}
		}
	}
	

	return 0;
}