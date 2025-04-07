// =================================================================
// File Name    : proxy_cache.c
// Date         : 2025/04/02
// OS           : Ubuntu 22.04 LTS 64bits
// Author       : Choe Hyeon Jin
// Student ID   : 2023202070
// -----------------------------------------------------------------
// Title        : System Programming proxy Assignment #1-1
// Description  : A program that converts the input URL into SHA1
//                and creates cache directory and file
// =================================================================

#include <stdio.h> // sprintf()
#include <string.h> // strcpy()
#include <openssl/sha.h> // SHA1()
#include <sys/types.h>
#include <unistd.h> // getuid(), chdir()
#include <pwd.h> // getpwuid()
#include <sys/stat.h> // mkdir(), umask()
#include <fcntl.h> // creat()
#include <time.h>
#include <dirent.h>

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

int createLogFile(char* home, int hit) {
	
	
}

// =================================================================
// Function     : main
// -----------------------------------------------------------------
// Input        : -
// Output       : int - 0 success
// Purpose      : Getting URL from user and creating cache file
//                based on SHA1 hash
// =================================================================

int main() {
	time_t startTime;
	time(&startTime);
	char input_url[256]; // input buffer
	char hashed_url[41]; // hashed buffer

	// get home dir path
	char home[256];
	getHomeDir(home);

	char root_path[300];
	sprintf(root_path, "%s/cache", home); // ~/cache
	umask(0);
	mkdir(root_path, 0777); // create cache directory

	char log_path[300];
	sprintf(log_path, "%s/logfile", home); // ~/logfile
	mkdir(log_path, 0777); // create cache directory
	chdir(log_path); // cd to ~/logfile
	FILE* fp = fopen("logfile.txt", "a"); // create log file

	int hit = 0;
	int miss = 0;
	while (1) {
		printf("input url> ");
		scanf("%s", input_url); // read input
		time_t t;
		time(&t);
		struct tm* lt = localtime(&t);

		if (strcmp(input_url, "bye") == 0) { // exit if input "bye"
			time_t endTime;
			time(&endTime);
			int runTime = endTime - startTime;
			fprintf(fp, "[Terminated] run time: %02d sec. #request hit : %d, miss : %d\n",
				runTime, hit, miss);
			fclose(fp);
			break;
		}
		sha1_hash(input_url, hashed_url); // get SHA1 hash URL

		char cache_dirname[4]; // first 3 letters
		strncpy(cache_dirname, hashed_url, 3);
		cache_dirname[3] = '\0';
		char dir_path[304];
		sprintf(dir_path, "%s/%s", root_path, cache_dirname); // ~/cache/[cache_dirname]

		chdir(root_path); // cd to ~/cache 
		mkdir(cache_dirname, 0777); // create cache subdir

		char cache_filename[38]; // remaining 37 letters
		strncpy(cache_filename, hashed_url + 3, 37);
		cache_filename[37] = '\0';

		// check if hit or miss
		int hitFlag = 0;
		struct dirent* pFile;
		DIR* pDir;
		pDir = opendir(cache_dirname);
		for (pFile = readdir(pDir); pFile; pFile = readdir(pDir)) {
			if (strcmp(pFile->d_name, cache_filename) == 0) { // hit
				hit++;
				hitFlag = 1;
				break;
			}
		}
		closedir(pDir);
		if (!hitFlag) { // miss
			chdir(dir_path); // cd to ~/cache/[cache_dirname]
			creat(cache_filename, 0777); // create cache file
			miss++;
		}
		
		chdir(log_path); // cd to ~/logfile
		if (!hitFlag) { // miss
			if (fp != NULL) {
				fprintf(fp, "[Miss]%s-[%02d/%02d/%02d, %02d:%02d:%02d]\n",
					input_url, lt->tm_year + 1900, lt->tm_mon + 1, 
					lt->tm_mday, lt->tm_hour, lt->tm_min, lt->tm_sec);
			}
		}
		else { // hit
			if (fp != NULL) {
				fprintf(fp, "[Hit]%s/%s-[%02d/%02d/%02d, %02d:%02d:%02d]\n",
					cache_dirname, cache_filename, lt->tm_year + 1900,
					lt->tm_mon + 1, lt->tm_mday, lt->tm_hour, lt->tm_min, lt->tm_sec);
				fprintf(fp, "[Hit]%s\n", input_url);
			}
		}
	}

	return 0;
}