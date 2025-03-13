#!/bin/python3

import os
import json
import requests

def list_unused_eab_keys(vault_token, vault_addr, vault_pki):
    """Function to list unused EAB keys from Vault."""
    url = f"{vault_addr}/v1/{vault_pki}/eab"
    headers = {"X-Vault-Token": vault_token}

    response = requests.request("LIST", url, headers=headers)
    if response.status_code != 200:
        raise Exception(f"Failed to list EAB keys: {response.text}")

    return response.json()

def revoke_eab_key(vault_token, vault_addr, vault_pki, eab_key):
    """Function to revoke an EAB key in Vault."""
    url = f"{vault_addr}/v1/{vault_pki}/eab/{eab_key}"
    headers = {"X-Vault-Token": vault_token}

    response = requests.delete(url, headers=headers)

    try:
        response_data = response.json()
        if "warnings" in response_data and response_data["warnings"]:
            print(f"\n⚠️ Warning: {response_data['warnings'][0]}")
        else:
            print(f"\n✅ Successfully revoked EAB key: {eab_key}")
    except json.JSONDecodeError:
        if response.status_code == 204:
            print(f"\n✅ Successfully revoked EAB key: {eab_key}")
        else:
            raise Exception(f"Failed to revoke EAB key: {response.text}")

def main():
    # Get environment variables or prompt for missing values
    vault_token = os.getenv("VAULT_TOKEN") or input("Enter VAULT_TOKEN: ")
    vault_addr = os.getenv("VAULT_ADDR") or input("Enter VAULT_ADDR: ")
    vault_pki = os.getenv("VAULT_PKI") or input("Enter VAULT_PKI: ")

    try:
        # List unused EAB keys
        eab_data = list_unused_eab_keys(vault_token, vault_addr, vault_pki)

        keys = eab_data.get("data", {}).get("keys", [])
        key_info = eab_data.get("data", {}).get("key_info", {})

        if not keys:
            print("No unused EAB keys found.")
            return

        print("\n🔹 Unused EAB Keys:")
        key_mapping = {}
        for idx, key in enumerate(keys, start=1):
            directory = key_info.get(key, {}).get("acme_directory", "Unknown Directory")
            key_mapping[idx] = key
            print(f"[{idx}] {key} (Directory: {directory})")

        # Prompt for key selection
        choice = int(input("\nEnter the number of the EAB key to revoke: "))
        if choice not in key_mapping:
            print("Invalid selection.")
            return

        selected_key = key_mapping[choice]

        # Revoke selected EAB key
        revoke_eab_key(vault_token, vault_addr, vault_pki, selected_key)

    except Exception as e:
        print(f"\n❌ Error: {e}")

if __name__ == "__main__":
    main()
