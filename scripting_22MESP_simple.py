
import requests
import socket
import ssl
from OpenSSL import crypto
import subprocess
import re

def get_ip_and_dns(domain):
    ip = socket.gethostbyname(domain)
    dns_name = socket.gethostbyaddr(ip)[0]
    return ip

def get_source_ip(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((ip, port))
    return s.getsockname()


def get_headers_and_content_type(response):
    headers = response.headers
    content_type = headers.get('Content-Type', 'Unknown')
    return headers, content_type

def get_cert_info(domain):
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
        s.connect((domain, 443))
        cert = s.getpeercert(binary_form=True)
    x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)
    return x509

def print_cert_info(cert):
    for i in range(cert.get_extension_count()):
        ext = cert.get_extension(i)
        print(f"{ext.get_short_name().decode()}: {ext}")

def traceroute(domain):
    result = subprocess.run(['tracert', domain], stdout=subprocess.PIPE, universal_newlines=True)
    return result.stdout.split("\n")

if __name__ == "__main__":

    domain = "taisen.fr"
    port = 443
    
    # Afficher l'IP et le nom du serveur DNS
    ip = get_ip_and_dns(domain)
    print(f"IP: {ip}")
    
    # Afficher l'IP et le port Source
    print(get_source_ip(ip, port))
  
    # Afficher l'IP et le port de destination
    print(f"Destination IP: {ip}, Destination Port: {port}")
    
    # Afficher les Headers
    headers, content_type = get_headers_and_content_type(requests.get(f"https://{domain}"))
    for header, value in headers.items():
        if header == "Access-Control-Allow-Origin":
            print(f"{header}: {value} : response header indicates whether the response can be shared with requesting code from the given origin.")
        else:
            print(f"{header}: {value}")


    # Stocker les différentes balises Web
    tags = re.findall(r'<(/?\w+)', requests.get(f"https://{domain}").text)
    tags = list(set(tags))
    print("Balises Web:", tags)
    

    # Afficher les différents éléments du certificat
    cert = get_cert_info(domain)
    print_cert_info(cert)
    for i in range(cert.get_extension_count()):
        ext = cert.get_extension(i)
        if ext.get_short_name() == b'authorityInfoAccess':
            print(ext)
    
    # Afficher la liste des IP équipements réseaux traversés
    hops = traceroute(domain)
    print("IPs des équipements réseaux traversés:")
    for hop in hops:
        print(hop)
