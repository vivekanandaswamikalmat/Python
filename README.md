# Python
Utility libs/scripts/programs using python




# DNS Simulator with ICMP Error Handling
# DNS_Error_response_simulator.py

**Author:** Vivekananda K

This Python script simulates a DNS server that can respond to DNS queries with various response codes (RCODEs) and also simulate ICMP errors.

## Features

* **DNS Response Simulation:**
    * Simulates DNS responses with RCODEs: `NOERROR`, `FORMERR`, `SERVFAIL`, `NOTIMPL`.
    * Handles EDNS OPT records, including COOKIE option removal.
    * Includes a dummy authority section in responses.
* **ICMP Error Simulation:**
    * Simulates ICMP "Destination Unreachable" errors (Type 3, Code 1).
    * Captures incoming packet information to create accurate ICMP error messages.
* **Clear Error Handling:**
    * Provides informative error messages for various exceptions.
* **Readability:**
    * Well-documented code with clear function and variable names.

## Requirements

* Python 2.7
* Root privileges (for sending raw ICMP packets)

## Usage

1.  **Run the script:**

    ```bash
    sudo python dns_simulator.py <response_type>
    ```

2.  **Replace `<response_type>` with one of the following:**

    * `NOERROR`: Successful DNS response.
    * `FORMERR`: Format error.
    * `SERVFAIL`: Server failure.
    * `NOTIMPL`: Not implemented.
    * `ICMP_ERROR`: Simulate an ICMP error.

## Example

To simulate a DNS server that responds with a `SERVFAIL` error:

```bash
sudo python dns_simulator.py SERVFAIL
