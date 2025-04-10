"""
DNS Simulator with ICMP Error Handling

Author: Vivekananda K
"""

import socket
import struct
import sys

def calculate_checksum(data):
    """Calculate the checksum for the given data."""
    checksum = 0
    data_length = len(data)
    for i in range(0, data_length, 2):
        if i + 1 < data_length:
            word = (ord(data[i]) << 8) + ord(data[i + 1])
        else:
            word = (ord(data[i]) << 8)
        checksum += word
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    return ~checksum & 0xFFFF

def create_icmp_error(original_ip_header, original_payload, icmp_type, icmp_code):
    """Create an ICMP error message."""
    icmp_type_code = struct.pack("!BB", icmp_type, icmp_code)
    unused_field = struct.pack("!H", 0)
    icmp_data = original_ip_header + original_payload[:8]  # Include original IP and 8 bytes of payload

    pseudo_header = icmp_type_code + unused_field + struct.pack("!H", 0) + icmp_data
    icmp_checksum = calculate_checksum(pseudo_header)

    icmp_header = icmp_type_code + struct.pack("!H", icmp_checksum) + unused_field
    return icmp_header + icmp_data

def send_icmp_error(target_ip, original_ip_header, original_payload, icmp_type=3, icmp_code=1):
    """Send an ICMP error message."""
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    icmp_packet = create_icmp_error(original_ip_header, original_payload, icmp_type, icmp_code)
    raw_socket.sendto(icmp_packet, (target_ip, 0))
    print "ICMP error sent to %s" % target_ip

def create_dns_response(query_data, response_code):
    """Creates a DNS response with the specified RCODE."""
    query_id = struct.unpack("!H", query_data[0:2])[0]
    response_flags = 0x8180 | response_code

    question_start_index = 12
    question_end_index = question_start_index
    while question_end_index < len(query_data):
        if query_data[question_end_index] == 0:
            question_end_index += 5
            break
        question_end_index += 1

    question_section = query_data[question_start_index:question_end_index]
    header_section = struct.pack("!HHHHHH", query_id, response_flags, 1, 0, 0, 0)
    return header_section + question_section

def simulate_dns_response(dns_socket, response_type, query_data, client_ip, client_port):
    """Simulates a DNS response and sends it back to the client."""
    try:
        if response_type == "ICMP_ERROR":
            original_packet, address = dns_socket.recvfrom(1024)
            original_ip_header = original_packet[:20]
            original_payload = original_packet[20:28]
            send_icmp_error(client_ip, original_ip_header, original_payload, icmp_type=3, icmp_code=1)
            return

        if response_type == "SERVFAIL":
            rcode = 2
        elif response_type == "FORMERR":
            rcode = 1
        elif response_type == "NOTIMPL":
            rcode = 4
        elif response_type == "NOERROR":
            rcode = 0
        else:
            print "Usage: python dns_simulator.py [SERVFAIL|FORMERR|NOTIMPL|NOERROR|ICMP_ERROR]"
            return

        dns_response = create_dns_response(query_data, rcode)
        dns_socket.sendto(dns_response, (client_ip, client_port))

        query_id = struct.unpack("!H", query_data[0:2])[0]
        print "Received query from %s:%s. ID: %s, RCODE: %s" % (client_ip, client_port, query_id, rcode)
        print "Sending response: %s" % dns_response.encode('hex')

    except Exception as error:
        print "Error: %s" % error

def main():
    """Main function to start the DNS simulator."""
    if len(sys.argv) != 2:
        print "Usage: python dns_simulator.py [SERVFAIL|FORMERR|NOTIMPL|NOERROR|ICMP_ERROR]"
        sys.exit(1)

    response_type = sys.argv[1]
    listen_ip = "10.58.177.208"
    listen_port = 5354

    dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns_socket.bind((listen_ip, listen_port))

    print "Listening on %s:%s" % (listen_ip, listen_port)

    while True:
        try:
            query_data, (client_address, client_port) = dns_socket.recvfrom(1024)
            simulate_dns_response(dns_socket, response_type, query_data, client_address, client_port)
        except Exception as error:
            print "Error during recvfrom: %s" % error

if __name__ == "__main__":
    main()
