#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <dirent.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <signal.h>
#include <wait.h>

const char *get_extension(const char *filename) {
	    const char *dot = strrchr(filename, '.');
		    if(!dot || dot == filename) return "";
			    return dot + 1;
}

char *output_txt(const char *filename) {
	const char *dot = strrchr(filename, '.');
	char *ret = (char *)malloc(dot - filename + 5);
	memcpy(ret, filename, dot - filename);
	strcat(ret, ".txt");
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
		char got_it[end-start+5];
		if (start != NULL){ 
//			while(byte_count++ <payload_length){
			memcpy(got_it, payload, end-start+2);
			for (int i = 8; i < end-start; i++) printf("%c",*(got_it+i)); //Choose whatever you want from payload :D
//			if (*temp_pointer == '\n') break;
//			printf("%c",*temp_pointer);
//			temp_pointer++;
//		}
			printf("\n");
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

	pid_t pid;
	int status;

	while (1) {
		pid = fork();
		dir = opendir("/root/pcap");
		if (pid == 0){ // I made this subprocess because of memory leak. Fortunately memory will be returned with this trick.
			while ((entry = readdir(dir)) != NULL){ //Iterates directory 
				if (strcmp(get_extension(entry -> d_name) ,"pcap") == 0 ) {
					sleep(5);
					total_packet_count = 10000000;//as much as you want
					snapshot_length = 1024;
					my_arguments = NULL;

					output_file = output_txt(entry->d_name);	
					freopen(output_file, "w+", stdout);//I did some weird stuff for my own purpose. Normally it's not necessary. 
					handle = pcap_open_offline(entry->d_name,error_buffer);
					pcap_loop(handle, total_packet_count, packet_parser, my_arguments); //So, this is where memory leaks.
					remove(entry -> d_name);
					freopen("/dev/tty", "w", stdout);
				}	
			
				if (strcmp(get_extension(entry -> d_name),"txt") == 0 ) {
					file = fopen(entry -> d_name, "r");
					char temp[255];
					char *line;
					while(!feof(file)) {
						line = fgets(temp, sizeof(temp), file);	
						if(line == NULL) continue;
						printf("%s", line);
					}
					fclose(file);
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
