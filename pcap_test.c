#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <dirent.h>

const char *get_filename_ext(const char *filename) {
	    const char *dot = strrchr(filename, '.');
		    if(!dot || dot == filename) return "";
			    return dot + 1;
}

int main(int argc, char* argv[]){
	//pid_t process_id = 0;
	//pid_t sid = 0;

	//process_id = fork();
	//if (process_id < 0) exit(1);
	//if (process_id > 0) exit(0);
	//umask(0);
	//
	//sid = setsid();
	//if(sid < 0) exit(1);
	//
	//close(STDIN_FILENO);
	//close(STDOUT_FILENO);
	//close(STDERR_FILENO);

	char path;
	dirent* entry;
	FILE* file = NULL;

	while (1) {
		DIR* dir = opendir("/root/pcap");
		while((entry = readdir(dir)) != NULL){
			if(strcmp(get_filename_ext(entry -> d_name) ,"pcap") == 0 ){
				//TODO

			}
			if(strcmp(get_filename_ext(entry -> d_name),"txt") == 0  ){
				file = fopen(entry -> d_name, "r");
				char strTemp[255];
				char *pStr;
				while(!feof( file)){
					pStr = fgets( strTemp, sizeof(strTemp), file);	
					printf("%s", pStr);
				}
				fclose(file);
			}
		}
		closedir(dir);
	}

	return (0);
}
