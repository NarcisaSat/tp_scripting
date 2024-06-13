# Web Information Script

This script performs several tasks to gather and display information about a specified domain. It retrieves the domain's IP address, source IP, HTTP headers, content type, HTML tags, SSL certificate information, and performs a traceroute to display the IPs of the network equipment traversed.

## Requirements

- Python 3.x
- Modules: `requests`, `socket`, `ssl`, `subprocess`, `re`

## Installation

1. Clone this repository or download the script file.
2. Ensure you have Python 3.x installed on your system.
3. Install the required modules using pip:
    ```sh
    pip install requests
    ```

## Usage

1. Run the script with the desired domain. The default domain in the script is `taisen.fr`.

    ```sh
    python web_info_script.py
    ```

2. The script will perform the following actions:
    - Perform an HTTP GET request to the domain.
    - Display the domain's IP address.
    - Display the local source IP address.
    - Display the destination IP and port.
    - Display the HTTP headers and content type.
    - Extract and display HTML tags from the response.
    - Display the SSL certificate information.
    - Perform a traceroute to the domain and display the IPs of the network equipment traversed.


