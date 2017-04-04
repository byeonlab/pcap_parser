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

const char *get_filename_ext(const char *filename) {
	    const char *dot = strrchr(filename, '.');
		    if(!dot || dot == filename) return "";
			    return dot + 1;
}

void packet_parser(
		u_char *args,
		const struct pcap_pkthdr *header,
		const u_char *packet
)
{
	struct ether_header *eth_header;
	eth_header = (struct ether_header *) packet;
	if (ntohs(eth_header -> ether_type) != ETHERTYPE_IP) {
		return;
	}

	const u_char *ip_header;
	const u_char *tcp_header;
	const u_char *payload;
	
	int ethernet_header_length = 14;
	int ip_header_length;
	int tcp_header_length;
	int payload_length;

	ip_header = packet + ethernet_header_length;
	ip_header_length = ((*ip_header) & 0x0f);
	ip_header_length = ip_header_length * 4;

	u_char protocol = *(ip_header + 9);
	if (protocol != IPPROTO_TCP) {
		return;
	}

	tcp_header = packet + ethernet_header_length + ip_header_length;
	tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
	tcp_header_length = tcp_header_length * 4;

	int total_headers_size = ethernet_header_length + ip_header_length + tcp_header_length;
	payload_length = header->caplen - 
		(ethernet_header_length + ip_header_length + tcp_header_length);
	payload = packet + total_headers_size;

	if (payload_length > 0) {
		const u_char *temp_pointer = payload;
		int byte_count = 0;
		if (*temp_pointer=='G' && *(temp_pointer+5*sizeof(char))=='j' && *(temp_pointer+6*sizeof(char))=='k') {
			while (byte_count++ < payload_length){
				if (*temp_pointer == '\n') break;
					printf("%c", *temp_pointer);
					temp_pointer++;
			}
			printf("\n");
		}
	}
	return;
}

int main(int argc, char** argv){
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

	const char path; 
	struct dirent* entry;
	FILE* file = NULL;


	char error_buffer[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	int snapshot_length = 1024;
	int total_packet_count = 100000000;
	u_char *my_arguments = NULL;

	DIR* dir = opendir("/root/pcap");
	while (1) {
		dir = opendir("/root/pcap");
		while((entry = readdir(dir)) != NULL){
			if(strcmp(get_filename_ext(entry -> d_name) ,"pcap") == 0 ) {
				freopen("stdout.txt", "w+", stdout);
				handle = pcap_open_offline(entry -> d_name, error_buffer);
				pcap_loop(handle, total_packet_count, packet_parser, my_arguments);
				remove(entry -> d_name);
				freopen("/dev/tty", "a", stdout);
			}
			if(strcmp(get_filename_ext(entry -> d_name),"txt") == 0 ) {
				file = fopen(entry -> d_name, "r");
				char temp[255];
				char *strptr;
				while(!feof( file)) {
					strptr = fgets(temp, sizeof(temp), file);	
					printf("%s", strptr);
				}
				fclose(file);
				remove(entry -> d_name);
			}
		}
		closedir(dir);
	}

	return (0);
}
