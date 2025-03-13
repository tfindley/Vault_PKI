#!/bin/python3

import os
import sys
import requests

def revoke_certificate(vault_token, vault_addr, vault_pki, serial_number):
    """Function to revoke a certificate in Vault using its serial number."""
    url = f"{vault_addr}/v1/{vault_pki}/revoke"
    headers = {"X-Vault-Token": vault_token}
    data = {"serial_number": serial_number}

    response = requests.post(url, headers=headers, json=data)

    if response.status_code != 200:
        raise Exception(f"Failed to revoke certificate: {response.text}")

    return response.json()

def main():
    # Get environment variables or prompt for missing values
    vault_token = os.getenv("VAULT_TOKEN") or input("Enter VAULT_TOKEN: ")
    vault_addr = os.getenv("VAULT_ADDR") or input("Enter VAULT_ADDR: ")
    vault_pki = os.getenv("VAULT_PKI") or input("Enter VAULT_PKI: ")

    # Check if serial number was provided as a command-line argument
    serial_number = sys.argv[1] if len(sys.argv) > 1 else input("Enter the Serial Number of the certificate to revoke: ").strip()

    try:
        # Revoke the certificate
        response_data = revoke_certificate(vault_token, vault_addr, vault_pki, serial_number)

        print(f"\n✅ Certificate with Serial Number {serial_number} has been revoked successfully!")
    except Exception as e:
        print(f"\n❌ Error: {e}")

if __name__ == "__main__":
    main()
