import requests
import socket
import ssl
from OpenSSL import crypto
import subprocess
import re

def get_ip_and_dns(domain):
    ip = socket.gethostbyname(domain)
    dns_name = socket.gethostbyaddr(ip)[0]
    return ip, dns_name

def get_source_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        source_ip = s.getsockname()[0]
    except Exception as e:
        source_ip = "N/A"
    finally:
        s.close()
    return source_ip

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
    hops = result.stdout.split("\n")
    ips = re.findall(r'\d+\.\d+\.\d+\.\d+', str(hops))
    return ips

def main():
    domain = "taisen.fr"
    response = requests.get(f"https://{domain}")
    
    # Afficher l'IP et le nom du serveur DNS
    ip, dns_name = get_ip_and_dns(domain)
    print(f"IP: {ip}, DNS: {dns_name}")
    
    # Afficher l'IP et le port Source
    source_ip = get_source_ip()
    print(f"Source IP: {source_ip}, Source Port: 443") # HTTPS default port is 443
    
    # Afficher l'IP et le port de destination
    print(f"Destination IP: {ip}, Destination Port: 443")
    
    # Afficher les Headers
    headers, content_type = get_headers_and_content_type(response)
    for header, value in headers.items():
        print(f"{header}: {value}")
    
    # Afficher le Content-Type
    print(f"Content-Type: {content_type}")

    # Stocker les différentes balises Web
    tags = re.findall(r'<(/?\w+)', response.text)
    tags = list(set(tags))
    print("Balises Web:", tags)
    
    # Afficher les différents éléments du certificat
    cert = get_cert_info(domain)
    print("Certificat:")
    print_cert_info(cert)
    
    # Afficher les noms de certificats de la chaîne de confiance
    print("Noms de certificats de la chaîne de confiance:")
    for i in range(cert.get_extension_count()):
        ext = cert.get_extension(i)
        if ext.get_short_name() == b'authorityInfoAccess':
            print(ext)
    
    # Afficher la liste des IP équipements réseaux traversés
    ips = traceroute(domain)
    print("IPs des équipements réseaux traversés:")
    for ip in ips:
        print(ip)

if __name__ == "__main__":
    main()
