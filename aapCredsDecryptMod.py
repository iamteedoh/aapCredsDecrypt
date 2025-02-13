#!/usr/bin/env python

import sys
import json
from datetime import datetime

print("DEBUG: The script has started running.")

try:
    # AWX/AAP specific imports
    from awx.main.models import (
        Credential, CredentialType, Organization, Project,
        JobTemplate, Team, Role
    )
    from awx.main.utils import decrypt_field
    from django.db.models import Q  # For constructing query filters
    print("DEBUG: Imports succeeded.")
except ImportError:
    print("ERROR: This script must be run within the AWX/AAP environment.")
    print("       For example, run 'awx-manage shell_plus' then 'exec(open(\"/path/to/script.py\").read())'")
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

def get_teams_from_role(role):
    """
    Dynamically determine the teams associated with a Role object.
    Handles differences between AWX/AAP versions.
    """
    teams = []
    if hasattr(role, 'team_set'):
        teams = list(role.team_set.all())
    elif hasattr(role, 'teams'):
        teams = list(role.teams.all())
    else:
        for related_object in role._meta.related_objects:
            if related_object.related_model == Team:
                filter_kwargs = {related_object.field.name: role}
                teams = list(Team.objects.filter(**filter_kwargs))
                break
    if not teams:
        print(f"WARNING: Could not find related teams for role: {role}. Skipping team access.")
    return teams

def decrypt_single_credential(cred):
    """
    Given a Credential object, return a dictionary containing its details
    along with its inputs (each field includes its internal id, a display label,
    and its value [decrypted if secret]).
    """
    ct = cred.credential_type
    # Attempt to load field definitions (labels, etc.) from the credential type's inputs.
    field_defs = {}
    try:
        if isinstance(ct.inputs, dict):
            fields_list = ct.inputs.get("fields", [])
            # Build a mapping keyed by field id.
            field_defs = { field.get("id"): field for field in fields_list if "id" in field }
    except Exception as e:
        print(f"DEBUG: Unable to load field definitions for credential type {ct.name}: {e}")
        field_defs = {}

    cred_info = {
        "id": cred.id,
        "name": cred.name,
        "credential_type": ct.name,
        "created": cred.created.isoformat() if cred.created else None,
        "modified": cred.modified.isoformat() if cred.modified else None,
        "organization": None,
        "access_list": [],
        "related_job_templates": [],
        # "fields" will be a list of objects (each with id, label, and value)
        "fields": [],
    }

    if cred.organization:
        cred_info["organization"] = {
            "id": cred.organization.id,
            "name": cred.organization.name
        }

    # Build access list for each role (admin, use, read).
    for role_attr in ['admin_role', 'use_role', 'read_role']:
        role_obj = getattr(cred, role_attr, None)
        if role_obj:
            for user in role_obj.members.all():
                cred_info["access_list"].append({
                    "type": "user",
                    "id": user.id,
                    "username": user.username,
                    "role": role_attr.replace('_role', '')
                })
            for team in get_teams_from_role(role_obj):
                cred_info["access_list"].append({
                    "type": "team",
                    "id": team.id,
                    "name": team.name,
                    "role": role_attr.replace('_role', '')
                })

    # Job Templates directly linked via the many-to-many field "credentials"
    for jt in JobTemplate.objects.filter(credentials=cred):
        cred_info["related_job_templates"].append({
            "id": jt.id,
            "name": jt.name,
            "type": "job_template"
        })

    # Job Templates associated via projects.
    filter_query = Q(credential_id=cred.id)
    if 'scm_credential' in [f.name for f in Project._meta.get_fields()]:
        filter_query |= Q(scm_credential_id=cred.id)
    for proj in Project.objects.filter(filter_query):
        for jt in JobTemplate.objects.filter(project_id=proj.id):
            cred_info["related_job_templates"].append({
                "id": jt.id,
                "name": jt.name,
                "type": "job_template_via_project",
                "project_id": proj.id,
                "project_name": proj.name
            })

    # Process each input field.
    fields_output = []
    for key, value in cred.inputs.items():
        if value is not None:
            # If the field is secret, attempt decryption.
            if key in SECRET_FIELDS:
                try:
                    actual_value = decrypt_field(cred, key)
                except Exception as e:
                    print(f"ERROR: Failed to decrypt field {key} for credential {cred.id}: {e}")
                    actual_value = None
            else:
                actual_value = value

            # Look up the display label from the field definitions; if not present, default to the key.
            label = field_defs.get(key, {}).get("label", key)
            fields_output.append({
                "id": key,
                "label": label,
                "value": actual_value,
            })
    cred_info["fields"] = fields_output

    return cred_info

def decrypt_credentials_by_ids(ids_list):
    """
    Given a list of credential IDs, decrypt them and return a list of decrypted credentials.
    """
    creds = Credential.objects.filter(id__in=ids_list)
    results = []
    for cred in creds:
        results.append(decrypt_single_credential(cred))
    return results

def decrypt_all_credentials():
    """
    Decrypt all credentials in the system.
    """
    creds = Credential.objects.all()
    results = []
    for cred in creds:
        results.append(decrypt_single_credential(cred))
    return results

def output_results(decrypted):
    """
    Output the decrypted credentials either to stdout or to a file per user choice.
    """
    if decrypted:
        # Remove duplicate job template entries per credential.
        for cred in decrypted:
            unique_jts = {tuple(sorted(d.items())) for d in cred['related_job_templates']}
            cred['related_job_templates'] = [dict(t) for t in unique_jts]

        output_json = json.dumps(decrypted, indent=2)
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

        if choice in ["1", "3"]:
            print("\n===== DECRYPTED CREDENTIALS =====")
            print(output_json)
            print("=================================\n")

        if choice in ["2", "3"]:
            filename = input("Enter filename to save credentials (e.g., /tmp/creds.json): ").strip()
            try:
                with open(filename, "w") as f:
                    f.write(output_json)
                print(f"Credentials saved to {filename}\n")
            except Exception as e:
                print(f"Error writing file: {e}")
    else:
        print("\nNo credentials to display or export.\n")

def main():
    print("DEBUG: Entered main()")
    print("Do you want to decrypt:")
    print("  a) All credentials")
    print("  s) Specific credentials (choose from a list)")
    print("  [Enter] to skip")
    option = input("Enter 'a' or 's': ").strip().lower()

    decrypted = []
    if option == 'a':
        print("\nDecrypting ALL credentials...\n")
        decrypted = decrypt_all_credentials()
    elif option == 's':
        # List available credentials.
        creds = Credential.objects.all().order_by("id")
        if not creds:
            print("No credentials found.\n")
            sys.exit(0)
        print("\nAvailable Credentials:")
        for cred in creds:
            print(f"  {cred.id}) {cred.name} (Type: {cred.credential_type.name})")
        selection = input("Enter comma separated list of credential IDs to decrypt: ").strip()
        try:
            selected_ids = [int(x.strip()) for x in selection.split(",") if x.strip().isdigit()]
        except Exception as e:
            print(f"Error processing input: {e}")
            sys.exit(1)
        if not selected_ids:
            print("No valid credential IDs entered. Exiting.\n")
            sys.exit(0)
        print("\nDecrypting selected credentials...\n")
        decrypted = decrypt_credentials_by_ids(selected_ids)
    else:
        print("\nSkipping credential decryption.\n")
        sys.exit(0)

    output_results(decrypted)

# For interactive environments like AWX's shell_plus, call main() directly.
main()

