import socket
import struct
import sys

def calculate_checksum(data):
    """Calculate the checksum for the given data."""
    checksum = 0
    n = len(data)
    for i in range(0, n, 2):
        if i + 1 < n:
            word = (ord(data[i]) << 8) + ord(data[i + 1])
        else:
            word = (ord(data[i]) << 8)
        checksum += word
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    return ~checksum & 0xFFFF

def create_icmp_error(orig_ip_header, orig_payload, icmp_type, icmp_code):
    """Create an ICMP error message."""
    # ICMP header
    icmp_type_code = struct.pack("!BB", icmp_type, icmp_code)
    icmp_checksum = 0
    unused_field = struct.pack("!H", 0)

    # Include original IP header and first 8 bytes of payload
    icmp_data = orig_ip_header + orig_payload[:8]

    # Calculate checksum
    pseudo_header = icmp_type_code + unused_field + struct.pack("!H", icmp_checksum) + icmp_data
    icmp_checksum = calculate_checksum(pseudo_header)

    # Rebuild ICMP header with correct checksum
    icmp_header = icmp_type_code + struct.pack("!H", icmp_checksum) + unused_field

    return icmp_header + icmp_data

def send_icmp_error(target_ip, orig_ip_header, orig_payload, icmp_type=3, icmp_code=1):
    """Send an ICMP error message."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    # Create ICMP error message
    icmp_error_packet = create_icmp_error(orig_ip_header, orig_payload, icmp_type, icmp_code)

    # Send the packet
    sock.sendto(icmp_error_packet, (target_ip, 0))
    print "ICMP error sent to %s" % target_ip

def simulate_dns_response(sock, response_type, query_data, client_address, client_port):
    """Simulates a DNS response and sends it back to the client."""

    try:
        if response_type == "ICMP_ERROR":
            # Capture incoming packet dynamically
            orig_packet, addr = sock.recvfrom(1024)
            
            # Parse original IP header (first 20 bytes)
            orig_ip_header = orig_packet[:20]
            
            # Extract original payload (next 8 bytes)
            orig_payload = orig_packet[20:28]
            
            # Send ICMP Destination Unreachable error
            send_icmp_error(client_address, orig_ip_header, orig_payload, icmp_type=3, icmp_code=1)  # Type 3: Destination Unreachable; Code 1: Host Unreachable
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

        response = create_dns_response(query_data, rcode)

        # Send response back to the client using the same socket
        sock.sendto(response, (client_address, client_port))

        query_id = struct.unpack("!H", query_data[0:2])[0]
        print "Received query from %s:%s. ID: %s, RCODE: %s" % (client_address, client_port, query_id, rcode)
        print "Sending response: %s" % response.encode('hex')

    except Exception as e:
        print "Error: %s" % e

def create_dns_response(query_data, rcode):
    """Creates a DNS response with the specified RCODE."""

    query_id = struct.unpack("!H", query_data[0:2])[0]
    response_flags = 0x8180 | rcode

    question_start = 12
    question_end = question_start
    while question_end < len(query_data):
        if query_data[question_end] == 0:
            question_end += 5
            break
        question_end += 1

    question_section = query_data[question_start:question_end]

    header_section = struct.pack("!HHHHHH", query_id, response_flags, 1, 0, 0, 0)

    return header_section + question_section

def main():
    if len(sys.argv) != 2:
        print "Usage: python dns_simulator.py [SERVFAIL|FORMERR|NOTIMPL|NOERROR|ICMP_ERROR]"
        sys.exit(1)

    response_type = sys.argv[1]
    listen_ip = "10.58.177.208"
    listen_port = 5354

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((listen_ip, listen_port))

    print "Listening on %s:%s" % (listen_ip, listen_port)

    while True:
        try:
            query_data, (client_address, client_port) = sock.recvfrom(1024)
            simulate_dns_response(sock, response_type, query_data, client_address, client_port)
        except Exception as e:
            print "Error during recvfrom: %s" % e

if __name__ == "__main__":
    main()
