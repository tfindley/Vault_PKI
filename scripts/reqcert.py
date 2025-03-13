#!/bin/python3

import os
import json
import requests

def request_certificate(vault_token, vault_addr, vault_pki, vault_pki_role, cn, san_dns, san_ips, ttl):
    """Function to request a certificate from Vault."""
    url = f"{vault_addr}/v1/{vault_pki}/issue/{vault_pki_role}"
    headers = {"X-Vault-Token": vault_token}

    # Build the data payload
    data = {
        "common_name": cn,
        "dns_sans": san_dns,
        "ip_sans": san_ips,
        "ttl": ttl
    }

    # Make the POST request to Vault
    response = requests.post(url, headers=headers, json=data)

    if response.status_code != 200:
        raise Exception(f"Failed to request certificate from Vault: {response.text}")

    return response.json()

def save_certificate(cert_data, cn):
    """Function to save the certificate files in a directory named after the CN."""
    cert_dir = cn

    # Create the directory if it doesn't exist
    os.makedirs(cert_dir, exist_ok=True)

    # Save cert.pem
    with open(f"{cert_dir}/cert.pem", "w") as f:
        f.write(cert_data["data"]["certificate"])

    # Save fullchain.pem
    with open(f"{cert_dir}/fullchain.pem", "w") as f:
        fullchain = cert_data["data"]["certificate"] + "\n" + "\n".join(cert_data["data"]["ca_chain"])
        f.write(fullchain)

    # Save chain.pem
    with open(f"{cert_dir}/chain.pem", "w") as f:
        f.write("\n".join(cert_data["data"]["ca_chain"]))

    # Save privkey.pem
    with open(f"{cert_dir}/privkey.pem", "w") as f:
        f.write(cert_data["data"]["private_key"])

    print(f"\n✅ Certificates and private key have been saved in: '{cert_dir}/'")

def prompt_for_sans(field_name):
    """Function to prompt for SANs and return a list."""
    sans = []
    while True:
        user_input = input(f"Enter a {field_name} SAN (or press Enter to finish): ").strip()
        if user_input:
            sans.append(user_input)
        else:
            break
    return sans

def validate_ttl(ttl):
    """Function to validate TTL format."""
    if not ttl:
        raise ValueError("TTL must not be empty.")

    # Basic validation for duration (e.g., 2769d, 3h, etc.)
    if ttl[-1] not in ['d', 'h', 'm', 's']:
        raise ValueError("Invalid TTL format. Please end TTL with a valid duration unit (d, h, m, s).")

    return ttl

def main():
    # Get environment variables or prompt for missing values
    vault_token = os.getenv("VAULT_TOKEN") or input("Enter VAULT_TOKEN: ")
    vault_addr = os.getenv("VAULT_ADDR") or input("Enter VAULT_ADDR: ")
    vault_pki = os.getenv("VAULT_PKI") or input("Enter VAULT_PKI: ")
    vault_pki_role = os.getenv("VAULT_PKI_ROLE") or input("Enter VAULT_PKI_ROLE: ")

    # Prompt for the Common Name (CN)
    cn = input("Enter the Common Name (CN): ").strip()

    # Prompt for the TTL (Time-to-Live)
    ttl = input("Enter the TTL (e.g., 2769d, 24h, 60m): ").strip()
    try:
        ttl = validate_ttl(ttl)  # Validate TTL format
    except ValueError as e:
        print(f"❌ Error: {e}")
        return

    # Prompt for DNS SANs
    san_dns = prompt_for_sans("DNS")

    # Prompt for IP SANs
    san_ips = prompt_for_sans("IP")

    try:
        # Request the certificate from Vault
        cert_data = request_certificate(vault_token, vault_addr, vault_pki, vault_pki_role, cn, san_dns, san_ips, ttl)

        # Save the certificate and related files
        save_certificate(cert_data, cn)

        # Extract and print the serial number
        serial_number = cert_data["data"]["serial_number"]
        print(f"\n🔹 Certificate Serial Number: {serial_number}")
        print(f"🎉 Certificate request successful!")

    except Exception as e:
        print(f"\n❌ Error: {e}")

if __name__ == "__main__":
    main()
