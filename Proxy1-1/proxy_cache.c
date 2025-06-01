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
	struct passwd *usr_info = getpwuid(getuid());
	strcpy(home, usr_info->pw_dir);

	return home;
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
	char input_url[256]; // input buffer
	char hashed_url[41]; // hashed buffer

	// get home dir path
	char home[256];
	getHomeDir(home);

	char root_dirname[300];
	sprintf(root_dirname, "%s/cache", home); // ~/cache

	umask(0);
	mkdir(root_dirname, 0777); // create cache directory

	while (1) {
		printf("input url> ");
		scanf("%s", input_url); // read input
		if (strcmp(input_url, "bye") == 0) break; // exit if "bye"

		sha1_hash(input_url, hashed_url); // get SHA1 hash URL

		char cache_dirname[4]; // first 3 letters
		strncpy(cache_dirname, hashed_url, 3);
		cache_dirname[3] = '\0';

		chdir(root_dirname); // cd to ~/cache 
		mkdir(cache_dirname, 0777); // create cache subdir
		
		char cache_filename[38]; // remaining 37 letters
		strncpy(cache_filename, hashed_url + 3, 37);
		cache_filename[37] = '\0';
		chdir(cache_dirname); // cd into subdir
		// check if file exists
		struct stat st;
		if (stat(cache_filename, &st) == -1) {
			// file doesn't exist create cache file
			creat(cache_filename, 0777);
		}
	}

	return 0;
}
