#!/bin/python3

import os
import json
import requests

def request_eab(vault_token, vault_addr, vault_pki, vault_pki_role):
    """Function to request an EAB from Vault."""
    url = f"{vault_addr}/v1/{vault_pki}/roles/{vault_pki_role}/acme/new-eab"
    headers = {"X-Vault-Token": vault_token}

    # Make the POST request to Vault
    response = requests.post(url, headers=headers)

    if response.status_code != 200:
        raise Exception(f"Failed to request EAB from Vault: {response.text}")

    return response.json()

def main():
    # Get environment variables or prompt for missing values
    vault_token = os.getenv("VAULT_TOKEN") or input("Enter VAULT_TOKEN: ")
    vault_addr = os.getenv("VAULT_ADDR") or input("Enter VAULT_ADDR: ")
    vault_pki = os.getenv("VAULT_PKI") or input("Enter VAULT_PKI: ")
    vault_pki_role = os.getenv("VAULT_PKI_ROLE") or input("Enter VAULT_PKI_ROLE: ")

    try:
        # Request the EAB from Vault
        eab_data = request_eab(vault_token, vault_addr, vault_pki, vault_pki_role)

        # Extract and print the EAB ID and Key
        eab_id = eab_data["data"]["id"]
        eab_key = eab_data["data"]["key"]
        print(f"\n🔹 EAB ID: {eab_id}")
        print(f"🔹 EAB Key: {eab_key}")
        print(f"🎉 EAB request successful!")

    except Exception as e:
        print(f"\n❌ Error: {e}")

if __name__ == "__main__":
    main()
