import os
import sys
import json
from scapy.all import *

def extract_attachments(pcap_file, output_dir):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    packets = rdpcap(pcap_file)
    extracted_files = []

    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(IP) and (pkt.haslayer(SMB2WriteRequest) or pkt.haslayer(SMB2ReadRequest)):
            try:
                data = bytes(pkt[TCP].payload)
                filename = f"{pkt[IP].src}_{pkt[TCP].sport}_{pkt[IP].dst}_{pkt[TCP].dport}_{pkt.time}.dat"
                file_path = os.path.join(output_dir, filename)
                with open(file_path, 'wb') as f:
                    f.write(data)
                extracted_files.append({
                    'file_name': filename,
                    'file_size': len(data),
                    'source_ip': pkt[IP].src,
                    'source_port': pkt[TCP].sport,
                    'destination_ip': pkt[IP].dst,
                    'destination_port': pkt[TCP].dport
                })
            except Exception as e:
                print(f"Error extracting file from packet {pkt.summary()}: {e}")

    return extracted_files

def write_metadata_to_json(metadata, json_file):
    with open(json_file, 'w') as f:
        json.dump(metadata, f, indent=4)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 your_script.py input_pcap_file.pcap output_directory")
        sys.exit(1)
    
    input_pcap_file = sys.argv[1]
    output_dir = sys.argv[2]

    extracted_files = extract_attachments(input_pcap_file, output_dir)

    # Write metadata to JSON file
    metadata_file = os.path.join(output_dir, 'metadata.json')
    write_metadata_to_json(extracted_files, metadata_file)

    print(f"Extraction and metadata generation completed. Extracted files saved to {output_dir}")
    print(f"Metadata saved to {metadata_file}")
