#!/usr/bin/env python

import sys
import json
from datetime import datetime

print("DEBUG: The script has started running.")

try:
    # AWX and AAP specific imports
    from awx.main.models import Credential, CredentialType, Organization, Project, JobTemplate
    from awx.main.utils import decrypt_field
    from django.db.models import Q  # For querying access lists
    from awx.main.models import Role #import Role to examine
    print("DEBUG: Imports succeeded.")
except ImportError:
    print("ERROR: This script must be run within the AWX/AAP environment.")
    print("       For example, run 'awx-manage shell_plus' then 'exec(open(\"/path/of/script.py\").read())'")
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

def get_teams_from_role(role):
    """
    Dynamically determines how to get teams from a Role object.
    This function is the key to handling different AWX versions.
    """
    teams = []
    if hasattr(role, 'team_set'):
        # Newer AWX/AAP
        teams = list(role.team_set.all())
    elif hasattr(role, 'teams'):
        # Older AWX/AAP
        teams = list(role.teams.all())
    else:
        # Introspection to find related teams, if possible
        for attr_name in dir(role):
            attr = getattr(role, attr_name)
            # Check if the attribute is a manager and related to Teams
            if hasattr(attr, 'model') and attr.model == Team:
                try:
                    teams = list(attr.all())
                    break  # Stop after finding the first likely candidate
                except Exception:
                    pass #Ignore, we will report an error later.

    if not teams: #if still empty
        print(f"WARNING: Could not find related teams for role: {role}.  Skipping team access.")

    return teams


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
            "created": cred.created.isoformat() if cred.created else None,
            "modified": cred.modified.isoformat() if cred.modified else None,
            "organization": None,
            "access_list": [],
            "related_job_templates": [],
            "decrypted_fields": {},
        }

        # Organization
        if cred.organization:
            cred_info["organization"] = {
                "id": cred.organization.id,
                "name": cred.organization.name
            }

        # Access List (Users and Teams) - Now with dynamic team retrieval
        for role_name in ['admin_role', 'use_role', 'read_role']:
            role = getattr(cred, role_name)
            if role:
                for user in role.members.all():
                    cred_info["access_list"].append({
                        "type": "user",
                        "id": user.id,
                        "username": user.username,
                        "role": role_name.replace('_role', '')
                    })

                # Use the helper function to get teams
                for team in get_teams_from_role(role):
                    cred_info["access_list"].append({
                        "type": "team",
                        "id": team.id,
                        "name": team.name,
                        "role": role_name.replace('_role', '')
                    })


        # Job Templates
        for jt in JobTemplate.objects.filter(credential=cred):
            cred_info["related_job_templates"].append({
                "id": jt.id,
                "name": jt.name,
                "type": "job_template"
            })

        # Job Templates through projects.
        for proj in Project.objects.filter(Q(credential=cred) | Q(scm_credential=cred)):
            for jt in JobTemplate.objects.filter(project=proj):
                cred_info["related_job_templates"].append({
                    "id": jt.id,
                    "name": jt.name,
                    "type": "job_template_via_project",
                    "project_id": proj.id,
                    "project_name": proj.name
                })

        # Decrypt only the fields that exist in cred.inputs
        for field_name in SECRET_FIELDS:
            if field_name in cred.inputs:
                try:
                    value = decrypt_field(cred, field_name)
                except Exception:
                    value = None
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

    # 1) Prompt user
    show_types = input("Do you want to list all used Credential Types? (y/n): ").strip().lower()
    if show_types == "y":
        used_types = list_used_credential_types()
        print("\nUsed Credential Types:")
        for ct in used_types:
            print(f"  - ID: {ct.id}, Name: {ct.name}")
        print()

    print("Do you want to see decrypted credentials for a specific Credential Type or for all used credentials?")
    show_creds = input("Enter 's' for specific, 'a' for all, or press [Enter] to skip: ").strip().lower()
    all_decrypted = []

    if show_creds == "s":
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
        print("\nDecrypting credentials for ALL used credential types...\n")
        all_decrypted = decrypt_all_used_types()

    else:
        print("\nSkipping credential decryption.\n")

    # 3) Output
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

        for cred in all_decrypted:
            cred['related_job_templates'] = [dict(t) for t in {tuple(d.items()) for d in cred['related_job_templates']}]

        output_json = json.dumps(all_decrypted, indent=2)

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

main()
