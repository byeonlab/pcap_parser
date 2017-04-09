#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
//#include <sys/types.h>
//#include <sys/stat.h>
#include <string.h>
#include <dirent.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
//#include <signal.h>
#include <wait.h>
/*
typedef struct {
	char **key;
	int *value;
	size_t key_used;
	size_t key_size;
	size_t value_used;
	size_t value_size;
} Dictionary;

void init_dict(Dictionary *dict) {
	dict -> key = malloc(1000000*sizeof(char*)); //key = (char *)malloc(sizeof(char));
	dict -> value = (int *)malloc(1000000*sizeof(int));
	dict -> key_used = 0;
	dict -> key_size = 0;
	dict -> value_used = 0;
	dict -> value_size = 0; 
}

void add_key(Dictionary *dict,  char *element) {
	if (dict -> key_used == dict -> key_size){
		dict-> key_size += (strlen(element)+1); 
		dict -> value_size += 1;
		dict -> key = realloc(dict->key, (dict -> key_size + strlen(element)+1) * sizeof(char*));
		dict -> key[dict -> key_used] = (char*)malloc(sizeof(char)*(strlen(element)+1));
		dict -> value = (int *)realloc(dict -> value, dict -> value_size * sizeof(int));
	}
	dict -> key[dict -> key_used++] = element;
	dict -> value[dict -> value_used++] = 1;
}
*/  // To use struct above, dynamic memory allocation of struct should be done( some realloc() problem due to dynamic array in static struct)

int search_key(char **key, int key_length, const char *line) {  //find if certain string exists in string array and returns index. Returns -1 if not exists.
	for (int i = 0; i < key_length; i++) {
		if (strcmp(key[i], line) == 0) return i;
	}
	return -1;
}

const char *get_extension(const char *filename) { //Get file extension.
	const char *dot = strrchr(filename, '.');
	if(!dot || dot == filename) return "";
	return dot + 1;
}

char *strip_line(const char *element){//get rid of '\n's at the end of the string.
	char* stripped;
	//stripped = (char *)malloc(strlen(element) * sizeof(char));
	int str_len, count = 0;
	for (int i = 0; i <strlen(element); i++){
		if(element[i] != '\n'){
		   	count++;
		}
	}
	str_len = count;
	stripped = (char *)malloc(str_len + 1);
   	memcpy(stripped, element, str_len);
    //stripped[str_len] = '\n';	
	stripped[str_len] = 0;
    return stripped;
}

char *change_extension(const char *filename, const char *extension) { //change file extension.
	char *dot = strrchr(filename, '.');
	char *ret = (char *)malloc(sizeof(char));
	ret = realloc(ret, dot - filename + strlen(extension)+1);
	memcpy(ret, filename, dot - filename);
	strcat(ret, extension);
	return ret;
}

void packet_parser(
		u_char *args,
		const struct pcap_pkthdr *header,
		const u_char *packet
)
{
	struct ether_header *eth_header;
	eth_header = (struct ether_header *) packet;
	if (ntohs(eth_header -> ether_type) != ETHERTYPE_IP) return;
	
	const u_char *ip_header;
	const u_char *tcp_header;
	const u_char *payload;
	
	int ethernet_header_length = 14;
	int ip_header_length;
	int tcp_header_length;
	int payload_length;

	ip_header = packet + ethernet_header_length;
	ip_header_length = ((*ip_header) & 0x0f) * 4;

	u_char protocol = *(ip_header + 9);
	if (protocol != IPPROTO_TCP) return;

	tcp_header = packet + ethernet_header_length + ip_header_length;
	tcp_header_length = (((*(tcp_header + 12)) & 0xF0) >> 4) * 4;

	int total_headers_size = ethernet_header_length + ip_header_length + tcp_header_length;
	payload_length = header->caplen - total_headers_size;
	payload = packet + total_headers_size;
	
	if (payload_length > 0) {
		const u_char *temp_pointer = payload;
		char *start = strstr(payload, "GET /jk?"); //I want to get this part of URI in payload
		char *end = strstr(payload, "&p=");
		int byte_count=0;	
		int count = 0;
		char *got_it;
		if (start != NULL){ 
			start = strchr(payload, '?');
			end = strchr(payload, '&');
			got_it = (char *)malloc((end-start)/sizeof(char));
//			while(byte_count++ <payload_length){
			//memcpy(got_it, payload, end-start+2);
			for (char* i = (start + sizeof(char)); i < end; i+= sizeof(char)) {
				//printf("%c",*i); //Choose whatever you want from payload :D
				got_it[count] = *i;
				count++;
			}
			got_it[count] = 0;
			printf("\n%s",got_it);

			free(got_it);
			got_it = NULL;
//			if (*temp_pointer == '\n') break;
//			printf("%c",*temp_pointer);
//			temp_pointer++;
		}
	}
	return;
}

int main(){
/*This program parses .pcap file and save the parsed part to .txt file
Then it opens the .txt file, prints it out and deletes the file.
Modify this the way you want this to be*/
	struct dirent* entry;
	FILE* file = NULL;

	char error_buffer[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	int snapshot_length;
	int total_packet_count;
	u_char *my_arguments;

	DIR* dir; 
	char* output_file;
	char* json;

	pid_t pid;
	int status;

	while (1) {
		pid = fork();
		dir = opendir("/root/pcap");

		if (pid == 0){ // I made this subprocess because of memory leak. Fortunately memory will be returned with this trick.
			while ((entry = readdir(dir)) != NULL){ //Iterates directory 
				if (strcmp(get_extension(entry -> d_name) ,"pcap") == 0 ) {
					sleep(5); //wait for pcap file to be completely copied.

					total_packet_count = 10000000;//as much as you want
					snapshot_length = 1024;
					my_arguments = NULL;

					output_file = change_extension(entry->d_name, ".txt");	
					freopen(output_file, "w+", stdout);//I did some weird stuff for my own purpose. Normally it's not necessary. 
					handle = pcap_open_offline(entry->d_name,error_buffer);
					pcap_loop(handle, total_packet_count, packet_parser, my_arguments); //So, this is where memory leaks.
					remove(entry -> d_name);
					freopen("/dev/tty", "w", stdout);
				}	
				if (strcmp(get_extension(entry -> d_name),"txt") == 0 ) {
					json = change_extension(entry -> d_name, ".json");
					file = fopen(entry -> d_name, "r");
					char temp[255];
					char *line, *line_stripped;

					char **key;
					int *value;
					int count = 0;
					int if_exist;
					size_t key_size = 0, value_size = 0;	

					key = malloc(sizeof(char*));
					value = (int *)malloc(sizeof(int*));

					while(!feof(file)) {
						line = fgets(temp, sizeof(temp), file);	
						if(line == NULL || *line == '\n') continue;
						line_stripped = (char *)malloc((strlen(line)) * sizeof(char));
						line_stripped = strip_line(line);

						if (count == 0 ) {

							key_size += (strlen(line_stripped) + 1);
							key = realloc(key, key_size * sizeof(char*));
							key[count] = (char *)malloc((strlen(line_stripped) + 1) * sizeof(char));

							value_size += 1;
							value = realloc(value, value_size * sizeof(int));

							key[count] = line_stripped;
							value[count] = 1;

							count ++;
						}
						else {
						   	if_exist = search_key(key, count, line_stripped);

							if (if_exist == -1) {
						
								key_size += (strlen(line_stripped) + 1);
								key = realloc(key, key_size * sizeof(char*));
								key[count] = (char *)malloc((strlen(line_stripped) + 1) * sizeof(char));

								value_size += 1;
								value = realloc(value, value_size * sizeof(int));

								key[count] = line_stripped;
								value[count] = 1;

								count ++;
							}
							else value[if_exist] += 1;
						}	
					}	
					free(line_stripped);
					line_stripped = NULL;
							
					fclose(file);
					FILE* json_file = NULL;

					json_file = fopen(json, "w+");

					fprintf(json_file,"{");
					for(int i = 0; i < count; i++){
						fprintf(json_file,"\"%s\":",key[i]);
						fprintf(json_file,"%d",value[i]);
						if (i != count-1) fprintf(file,", ");
					}
					fprintf(json_file,"}");
					fclose(json_file);
					free(key);
					free(value);
					key = NULL;
					value = NULL;
					remove(entry -> d_name);
				}
			}
			closedir(dir);
			return 0;
		}
		else if(pid < 0) return 1;

		else  waitpid(0, &status, 0);
		closedir(dir);
	}
	return 0;
}
