#!/usr/bin/env python

import sys
import json

print("DEBUG: The script has started running.")

try:
    # AWX and AAP specific imports
    from awx.main.models import Credential, CredentialType
    from awx.main.utils import decrypt_field
    print("DEBUG: Imports succeeded.")
except ImportError:
    print("ERROR: This script must be run within the AWX/AAP environment.")
    print("       For example, run 'awx-manage shell_plus' then
          'exec(open(\"/path/of/script.py\").read())'")
    sys.exit(1)

print("DEBUG: Past the try/except. About to define functions.")

# Encrypted fields we want to attempt to decrypt
SECRET_FIELDS = [
    "password",
    "ssh_key_data",
    "ssh_key_unlock",
    "become_password",
    "vault_password",
    "authorize_password",
    "secret",
    "secret_key",
    "security_token",
]

def list_used_credential_types():
    """
    Return a list of CredentialTypes that are actively used
    by existing Credential objects.
    """
    used_ct_ids = Credential.objects.values_list("credential_type_id", flat=True).distinct()
    return CredentialType.objects.filter(id__in=used_ct_ids)

def decrypt_credentials_by_type(cred_type):
    """
    Decrypt all credentials matching the provided CredentialType.
    Return a list of dicts with credential info.
    """
    creds = Credential.objects.filter(credential_type=cred_type)
    results = []

    for cred in creds:
        cred_info = {
            "id": cred.id,
            "name": cred.name,
            "credential_type": cred_type.name,
            "decrypted_fields": {},
        }
        # Decrypt only the fields that exist in cred.inputs
        for field_name in SECRET_FIELDS:
            if field_name in cred.inputs:
                try:
                    value = decrypt_field(cred, field_name)
                except Exception:
                    value = None  # or "ERROR DECRYPTING"
                cred_info["decrypted_fields"][field_name] = value

        results.append(cred_info)

    return results

def decrypt_all_used_types():
    """
    Decrypt all credentials for *all* used credential types.
    Return a combined list of all decrypted credentials.
    """
    all_results = []
    used_types = list_used_credential_types()
    for ct in used_types:
        all_results.extend(decrypt_credentials_by_type(ct))
    return all_results

print("DEBUG: About to enter main()")

def main():
    print("DEBUG: Entered main()")

    # 1) Prompt user: list all used Credential Types?
    show_types = input("Do you want to list all used Credential Types? (y/n): ").strip().lower()
    if show_types == "y":
        used_types = list_used_credential_types()
        print("\nUsed Credential Types:")
        for ct in used_types:
            print(f"  - ID: {ct.id}, Name: {ct.name}")
        print()

    # 2) Prompt user: "specific" or "all" or skip
    print("Do you want to see decrypted credentials for a specific Credential Type or for all used credentials?")
    show_creds = input("Enter 's' for specific, 'a' for all, or press [Enter] to skip: ").strip().lower()
    all_decrypted = []

    if show_creds == "s":
        # -- Decrypt one specific CredentialType --
        used_types = list_used_credential_types()
        if not used_types:
            print("No credential types found.\n")
            sys.exit(0)

        type_dict = {str(ct.id): ct for ct in used_types}

        print("Available Credential Types:")
        for ct in used_types:
            print(f"  {ct.id}) {ct.name}")
        print()

        selected_id = input("Enter the ID of the Credential Type you want to see: ").strip()
        if selected_id in type_dict:
            cred_type = type_dict[selected_id]
            print(f"\nDecrypting credentials of type: {cred_type.name}\n")
            all_decrypted = decrypt_credentials_by_type(cred_type)
        else:
            print("Invalid Credential Type ID selected. Exiting.\n")
            sys.exit(0)

    elif show_creds == "a":
        # -- Decrypt *all* used CredentialTypes --
        print("\nDecrypting credentials for ALL used credential types...\n")
        all_decrypted = decrypt_all_used_types()

    else:
        # If user pressed Enter or typed something else, skip.
        print("\nSkipping credential decryption.\n")

    # 3) Output results only if we have decrypted credentials
    if len(all_decrypted) > 0:
        choice = input(
            "How do you want to output the decrypted credentials?\n"
            "  1) Standard Output\n"
            "  2) Save to File\n"
            "  3) Both\n"
            "Choose [1, 2, or 3]: "
        ).strip()

        if choice not in ["1", "2", "3"]:
            print("Invalid choice. Exiting.\n")
            sys.exit(0)

        # Convert to JSON for easy reading
        output_json = json.dumps(all_decrypted, indent=2)

        if choice in ["1", "3"]:
            # Print to stdout
            print("\n===== DECRYPTED CREDENTIALS =====")
            print(output_json)
            print("=================================\n")

        if choice in ["2", "3"]:
            # Also (or only) save to file
            filename = input("Enter filename to save credentials (e.g., /tmp/creds.json): ").strip()
            try:
                with open(filename, "w") as f:
                    f.write(output_json)
                print(f"Credentials saved to {filename}\n")
            except Exception as e:
                print(f"Error writing file: {e}")
    else:
        print("\nNo credentials to display or export.\n")

# If you are calling this script with `exec(open("script.py").read())`,
# remove the conditional and call main() directly.

#if __name__ == "__main__":
#    main()

main()
