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
    Return a queryset of CredentialTypes that are actively used by existing Credential objects.
    """
    used_ct_ids = Credential.objects.values_list("credential_type_id", flat=True).distinct()
    return CredentialType.objects.filter(id__in=used_ct_ids)

def get_teams_from_role(role):
    """
    Dynamically determines how to get teams from a Role object.
    This handles differences between AWX/AAP versions.
    """
    teams = []
    if hasattr(role, 'team_set'):
        # Newer AWX/AAP versions
        teams = list(role.team_set.all())
    elif hasattr(role, 'teams'):
        # Older AWX/AAP versions
        teams = list(role.teams.all())
    else:
        # Fallback: use model introspection
        for related_object in role._meta.related_objects:
            if related_object.related_model == Team:
                filter_kwargs = {related_object.field.name: role}
                teams = list(Team.objects.filter(**filter_kwargs))
                break  # Use the first matching relationship

    if not teams:
        print(f"WARNING: Could not find related teams for role: {role}.  Skipping team access.")
    return teams

def decrypt_credentials_by_type(cred_type):
    """
    Decrypt all credentials matching the provided CredentialType.
    Returns a list of dictionaries containing credential info.
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
            # New key that displays all input fields (decrypted if needed)
            "fields": {},
        }

        # Organization info
        if cred.organization:
            cred_info["organization"] = {
                "id": cred.organization.id,
                "name": cred.organization.name
            }

        # Build the access list for users and teams
        for role_attr in ['admin_role', 'use_role', 'read_role']:
            role_obj = getattr(cred, role_attr, None)
            if role_obj:
                # Add users
                for user in role_obj.members.all():
                    cred_info["access_list"].append({
                        "type": "user",
                        "id": user.id,
                        "username": user.username,
                        "role": role_attr.replace('_role', '')
                    })
                # Add teams using our helper function
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

        # Job Templates through projects referencing this credential.
        filter_query = Q(credential_id=cred.id)
        # If the Project model has an 'scm_credential' field, include that in the query.
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

        # Process all credential input fields.
        # For keys that are in SECRET_FIELDS, attempt to decrypt the value.
        # For all others, just display the raw value.
        fields_output = {}
        for key, value in cred.inputs.items():
            # Display the field if it has a non-null value.
            if value is not None:
                if key in SECRET_FIELDS:
                    try:
                        dec_val = decrypt_field(cred, key)
                    except Exception as e:
                        print(f"ERROR: Failed to decrypt field {key} for credential {cred.id}: {e}")
                        dec_val = None
                    fields_output[key] = dec_val
                else:
                    fields_output[key] = value
        cred_info["fields"] = fields_output

        results.append(cred_info)

    return results

def decrypt_all_used_types():
    """
    Decrypt credentials for all used credential types.
    Returns a combined list of all decrypted credentials.
    """
    all_results = []
    used_types = list_used_credential_types()
    for ct in used_types:
        all_results.extend(decrypt_credentials_by_type(ct))
    return all_results

print("DEBUG: About to enter main()")

def main():
    print("DEBUG: Entered main()")

    # 1) Ask the user whether to list used Credential Types.
    show_types = input("Do you want to list all used Credential Types? (y/n): ").strip().lower()
    if show_types == "y":
        used_types = list_used_credential_types()
        print("\nUsed Credential Types:")
        for ct in used_types:
            print(f"  - ID: {ct.id}, Name: {ct.name}")
        print()

    # 2) Ask the user whether to decrypt specific or all credentials.
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

    # 3) Output the results if any credentials were decrypted.
    if all_decrypted:
        # Remove duplicate job template entries for each credential.
        for cred in all_decrypted:
            unique_jts = {tuple(sorted(d.items())) for d in cred['related_job_templates']}
            cred['related_job_templates'] = [dict(t) for t in unique_jts]

        output_json = json.dumps(all_decrypted, indent=2)

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

# For interactive environments like AWX's shell_plus, call main() directly.
main()

