# awx/main/management/commands/aapcreds.py

import os
import sys
import json
import argparse
import subprocess
import tempfile
from django.core.management.base import BaseCommand
from datetime import datetime

# AWX/AAP specific imports (they are already available in AWX's environment)
from awx.main.models import (
    Credential, CredentialType, Organization, Project,
    JobTemplate, Team, Role, User
)
from awx.main.utils import decrypt_field
from django.db.models import Q

# (Include your existing functions here: list_used_credential_types, decrypt_single_credential, etc.)

class Command(BaseCommand):
    help = "AWX/AAP Credential Export/Import Tool"

    def add_arguments(self, parser):
        parser.add_argument("--quiet", action="store_true", help="Run in non-interactive mode")
        parser.add_argument("--export", action="store_true", help="Export credentials")
        parser.add_argument("--export-file", type=str, help="File path to export credentials to (must be .json)")
        parser.add_argument("--import", dest="import_flag", action="store_true", help="Import credentials")
        parser.add_argument("--import-file", type=str, help="File path to import credentials from (must be .json)")
        parser.add_argument("--list-cred-types", action="store_true", help="List used credential types")
        parser.add_argument("--encrypt", action="store_true", help="Encrypt the exported file using ansible-vault")
        parser.add_argument("--vault-password-file", type=str, help="Full path of the vault password file for vault operations")

    def handle(self, *args, **options):
        # If running in quiet (non-interactive) mode, process the flags.
        if options.get("quiet"):
            self.run_non_interactive(options)
        else:
            # Otherwise, run the interactive main loop.
            self.main()

    def run_non_interactive(self, opts):
        # Example implementation based on your existing run_non_interactive code:
        if opts.get("list_cred_types"):
            types = list_used_credential_types()
            if not types:
                self.stdout.write("No credential types found.\n")
            else:
                self.stdout.write("Used Credential Types:")
                for ct in types:
                    self.stdout.write(f"  {ct.id}) {ct.name}")
        if opts.get("export"):
            if not opts.get("export_file"):
                self.stderr.write("Error: --export requires --export-file to be provided.\n")
                sys.exit(1)
            self.stdout.write("Decrypting ALL credentials for export...\n")
            decrypted = decrypt_all_credentials()
            for cred in decrypted:
                unique_jts = {tuple(sorted(d.items())) for d in cred['related_job_templates']}
                cred['related_job_templates'] = [dict(t) for t in unique_jts]
            output_json = json.dumps(decrypted, indent=2)
            try:
                with open(opts.get("export_file"), "w") as f:
                    f.write(output_json)
                self.stdout.write(f"Credentials exported to {opts.get('export_file')}\n")
            except Exception as e:
                self.stderr.write(f"Error writing export file: {e}\n")
            if opts.get("encrypt"):
                if not opts.get("vault_password_file"):
                    self.stderr.write("Error: --encrypt requires --vault-password-file to be provided.\n")
                    sys.exit(1)
                try:
                    subprocess.check_call([
                        "ansible-vault", "encrypt", opts.get("export_file"),
                        "--vault-password-file", opts.get("vault_password_file")
                    ])
                    self.stdout.write(f"Export file {opts.get('export_file')} encrypted using ansible-vault.\n")
                except Exception as e:
                    self.stderr.write(f"Error encrypting file: {e}\n")
        if opts.get("import_flag"):
            if not opts.get("import_file"):
                self.stderr.write("Error: --import requires --import-file to be provided.\n")
                sys.exit(1)
            try:
                with open(opts.get("import_file"), "r") as f:
                    first_line = f.readline()
                if first_line.startswith("$ANSIBLE_VAULT;"):
                    if not opts.get("vault_password_file"):
                        self.stderr.write("Error: The import file appears to be encrypted but no --vault-password-file provided.\n")
                        sys.exit(1)
                    temp_fd, temp_path = tempfile.mkstemp(suffix=".json")
                    os.close(temp_fd)
                    try:
                        subprocess.check_call([
                            "ansible-vault", "decrypt", opts.get("import_file"),
                            "--vault-password-file", opts.get("vault_password_file"),
                            "--output", temp_path
                        ])
                        self.stdout.write(f"Decrypted import file to temporary file: {temp_path}\n")
                        import_credentials_from_file(temp_path)
                    finally:
                        os.remove(temp_path)
                else:
                    import_credentials_from_file(opts.get("import_file"))
            except Exception as e:
                self.stderr.write(f"Error processing import file: {e}\n")

    def main(self):
        # Your interactive main loop code goes here.
        while True:
            self.stdout.write("-------------------------------------------------")
            self.stdout.write("Main Menu:")
            self.stdout.write("  1) List all used Credential Types")
            self.stdout.write("  2) Decrypt ALL credentials")
            self.stdout.write("  3) Decrypt specific credentials")
            self.stdout.write("  4) Import credentials from file")
            self.stdout.write("  5) Exit")
            option = input("Enter option [1-5]: ").strip()
            if option == "1":
                types = list_used_credential_types()
                if not types:
                    self.stdout.write("No credential types found.\n")
                else:
                    self.stdout.write("\nUsed Credential Types:")
                    for ct in types:
                        self.stdout.write(f"  {ct.id}) {ct.name}")
                    self.stdout.write("")
                input("Press Enter to return to the main menu...")
            elif option == "2":
                self.stdout.write("\nDecrypting ALL credentials...\n")
                decrypted = decrypt_all_credentials()
                output_results(decrypted)
                input("Press Enter to return to the main menu...")
            elif option == "3":
                creds = Credential.objects.all().order_by("id")
                if not creds:
                    self.stdout.write("No credentials found.\n")
                    input("Press Enter to return to the main menu...")
                    continue
                self.stdout.write("\nAvailable Credentials:")
                for cred in creds:
                    self.stdout.write(f"  {cred.id}) {cred.name} (Type: {cred.credential_type.name})")
                selection = input("Enter comma separated list of credential IDs to decrypt: ").strip()
                try:
                    selected_ids = [int(x.strip()) for x in selection.split(",") if x.strip().isdigit()]
                except Exception as e:
                    self.stderr.write(f"Error processing input: {e}\n")
                    input("Press Enter to return to the main menu...")
                    continue
                if not selected_ids:
                    self.stdout.write("No valid credential IDs entered.\n")
                    input("Press Enter to return to the main menu...")
                    continue
                self.stdout.write("\nDecrypting selected credentials...\n")
                decrypted = decrypt_credentials_by_ids(selected_ids)
                output_results(decrypted)
                input("Press Enter to return to the main menu...")
            elif option == "4":
                filename = input("Enter the filename (with path) of the JSON file to import (e.g., /tmp/creds.json): ").strip()
                import_credentials_from_file(filename)
                input("Press Enter to return to the main menu...")
            elif option == "5":
                self.stdout.write("Exiting.\n")
                break
            else:
                self.stdout.write("Invalid option. Please try again.\n")
