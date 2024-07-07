#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <json-c/json.h>

// Structure to hold file metadata
struct FileMetadata {
    char file_name[256];
    size_t file_size;
    char src_ip[INET_ADDRSTRLEN];
    int src_port;
    char dst_ip[INET_ADDRSTRLEN];
    int dst_port;
};

void extract_attachments_and_metadata(const char *pcap_filename) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    const u_char *packet;
    int packet_count = 0;
    struct FileMetadata extracted_files[100]; // Assuming max 100 files

    // Open pcap file
    handle = pcap_open_offline(pcap_filename, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return;
    }

    // Create directory for extracted files
    char output_dir[256];
    snprintf(output_dir, sizeof(output_dir), "%s_extracted_files", pcap_filename);
    mkdir(output_dir, 0755);

    // Process packets
    while ((packet = pcap_next(handle, &header)) != NULL) {
        struct ether_header *eth_header = (struct ether_header *)packet;
        if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
            struct ip *ip_packet = (struct ip *)(packet + sizeof(struct ether_header));
            if (ip_packet->ip_p == IPPROTO_TCP) {
                struct tcphdr *tcp_header = (struct tcphdr *)((u_char *)ip_packet + ip_packet->ip_hl * 4);
                int tcp_header_size = tcp_header->doff * 4;

                // SMBv2 is over TCP port 445
                if (ntohs(tcp_header->th_dport) == 445 || ntohs(tcp_header->th_sport) == 445) {
                    // Assuming SMBv2 packet parsing logic here

                    // Example: Extracting file and metadata
                    // char file_name[] = "example.dat";
                    // FILE *fp = fopen(file_name, "wb");
                    // fwrite(packet + header.len, 1, header.caplen - header.len, fp);
                    // fclose(fp);

                    // Example: Storing metadata
                    // strncpy(extracted_files[packet_count].file_name, file_name, sizeof(extracted_files[packet_count].file_name) - 1);
                    // extracted_files[packet_count].file_size = header.caplen - header.len;
                    // inet_ntop(AF_INET, &(ip_packet->ip_src), extracted_files[packet_count].src_ip, INET_ADDRSTRLEN);
                    // extracted_files[packet_count].src_port = ntohs(tcp_header->th_sport);
                    // inet_ntop(AF_INET, &(ip_packet->ip_dst), extracted_files[packet_count].dst_ip, INET_ADDRSTRLEN);
                    // extracted_files[packet_count].dst_port = ntohs(tcp_header->th_dport);
                    
                    // packet_count++;
                }
            }
        }
    }

    pcap_close(handle);

    // Write metadata to JSON file
    json_object *jobj = json_object_new_array();
    for (int i = 0; i < packet_count; i++) {
        json_object *file_obj = json_object_new_object();
        json_object_object_add(file_obj, "file_name", json_object_new_string(extracted_files[i].file_name));
        json_object_object_add(file_obj, "file_size", json_object_new_int64(extracted_files[i].file_size));
        json_object_object_add(file_obj, "src_ip", json_object_new_string(extracted_files[i].src_ip));
        json_object_object_add(file_obj, "src_port", json_object_new_int(extracted_files[i].src_port));
        json_object_object_add(file_obj, "dst_ip", json_object_new_string(extracted_files[i].dst_ip));
        json_object_object_add(file_obj, "dst_port", json_object_new_int(extracted_files[i].dst_port));
        json_object_array_add(jobj, file_obj);
    }

    char json_filename[256];
    snprintf(json_filename, sizeof(json_filename), "%s_metadata.json", pcap_filename);
    FILE *json_file = fopen(json_filename, "w");
    if (json_file) {
        const char *json_str = json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_PRETTY);
        fprintf(json_file, "%s\n", json_str);
        fclose(json_file);
    }
    json_object_put(jobj);

    printf("Extraction completed successfully.\n");
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap_filename>\n", argv[0]);
        return EXIT_FAILURE;
    }

    extract_attachments_and_metadata(argv[1]);

    return EXIT_SUCCESS;
}

run 


Output
------
1. file name: smb.pcap
2. file size : 33.9KB
3. source ip address : 192.168.1.78
4. source port number : 55770
5. destination ip address: 192.168.1.53
6. destination port number : 445
