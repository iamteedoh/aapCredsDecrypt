#!/usr/bin/env python

import sys
import json
from datetime import datetime

print("DEBUG: The script has started running.")

try:
    # AWX/AAP specific imports
    from awx.main.models import (
        Credential, CredentialType, Organization, Project,
        JobTemplate, Team, Role, User
    )
    from awx.main.utils import decrypt_field
    from django.db.models import Q  # For constructing query filters
    print("DEBUG: Imports succeeded.")
except ImportError:
    print("ERROR: This script must be run within the AWX/AAP environment.")
    print("       For example, run 'awx-manage shell_plus' then 'exec(open(\"/path/to/script.py\").read())'")
    sys.exit(1)

print("DEBUG: Passed the try/except. About to define functions.")

# Encrypted fields that should be decrypted.
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
    Return a queryset of CredentialTypes that are actively used by at least one Credential.
    """
    used_ct_ids = Credential.objects.values_list("credential_type_id", flat=True).distinct()
    return CredentialType.objects.filter(id__in=used_ct_ids)

def get_teams_from_role(role):
    """
    Return the list of teams associated with the given Role.
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
    Given a Credential object, return a dictionary containing its details and its input fields.
    Each input field is output as an object with:
       - id: the internal field name
       - label: the display label (pulled from the credential type's inputs, if available)
       - value: the plain or decrypted value (as returned by decrypt_field)
    """
    ct = cred.credential_type
    # Attempt to load field definitions from the credential type's inputs.
    field_defs = {}
    try:
        if isinstance(ct.inputs, dict):
            fields_list = ct.inputs.get("fields", [])
            field_defs = {field.get("id"): field for field in fields_list if "id" in field}
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
        "fields": [],
    }

    if cred.organization:
        cred_info["organization"] = {
            "id": cred.organization.id,
            "name": cred.organization.name
        }

    # Build access list for users and teams.
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
            if key in SECRET_FIELDS:
                try:
                    actual_value = decrypt_field(cred, key)
                except Exception as e:
                    print(f"ERROR: Failed to decrypt field {key} for credential {cred.id}: {e}")
                    actual_value = None
            else:
                actual_value = value

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
    Given a list of credential IDs, decrypt and return their details.
    """
    creds = Credential.objects.filter(id__in=ids_list)
    results = []
    for cred in creds:
        results.append(decrypt_single_credential(cred))
    return results

def decrypt_all_credentials():
    """
    Decrypt and return details for all credentials.
    """
    creds = Credential.objects.all()
    results = []
    for cred in creds:
        results.append(decrypt_single_credential(cred))
    return results

def output_results(decrypted):
    """
    Prompt the user for output options and display the decrypted credentials.
    """
    if decrypted:
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
            print("Invalid choice. Returning to main menu.\n")
            return

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

#
# Import functionality with duplicate check and master list.
#
def import_credential(cred_data, duplicates):
    """
    Given a credential dictionary (from the JSON export), import it into AWX/AAP.
    This function:
      - Looks up the CredentialType by name.
      - Looks up the Organization by id (if provided).
      - Checks for an existing credential with the same name, type, and organization.
      - Converts the "fields" list into an "inputs" dictionary.
      - Creates a new Credential if it doesn't already exist.
      - Attempts to re-establish the access_list and related_job_templates.
    The 'duplicates' list is used to record names of credentials that were skipped.
    """
    name = cred_data.get("name")
    ct_name = cred_data.get("credential_type")
    try:
        ct = CredentialType.objects.get(name=ct_name)
    except CredentialType.DoesNotExist:
        print(f"CredentialType '{ct_name}' not found for credential '{name}'. Skipping.")
        return None

    org_data = cred_data.get("organization")
    org = None
    if org_data and org_data.get("id"):
        try:
            org = Organization.objects.get(id=org_data.get("id"))
        except Organization.DoesNotExist:
            print(f"Organization with id {org_data.get('id')} not found for credential '{name}'. Using None.")

    # Check for existing credential.
    if Credential.objects.filter(name=name, credential_type=ct, organization=org).exists():
        print(f"Credential '{name}' already exists. Skipping import.")
        duplicates.append(name)
        return None

    # Build the inputs dictionary from the "fields" list.
    inputs = {}
    for field in cred_data.get("fields", []):
        field_id = field.get("id")
        field_value = field.get("value")
        if field_id:
            inputs[field_id] = field_value

    # Create the new Credential.
    try:
        cred_obj = Credential(
            name=name,
            credential_type=ct,
            organization=org,
            inputs=inputs
        )
        cred_obj.save()
        print(f"Imported credential: {name}")
    except Exception as e:
        print(f"Error importing credential '{name}': {e}")
        return None

    # Re-establish access_list.
    for access in cred_data.get("access_list", []):
        role_name = access.get("role")  # Expected: "admin", "use", or "read"
        if access.get("type") == "user":
            try:
                user = User.objects.get(id=access.get("id"))
            except Exception as e:
                print(f"Could not find user with id {access.get('id')} for credential '{name}'.")
                continue
            if role_name == "admin" and hasattr(cred_obj, "admin_role"):
                cred_obj.admin_role.members.add(user)
            elif role_name == "use" and hasattr(cred_obj, "use_role"):
                cred_obj.use_role.members.add(user)
            elif role_name == "read" and hasattr(cred_obj, "read_role"):
                cred_obj.read_role.members.add(user)
        elif access.get("type") == "team":
            try:
                team = Team.objects.get(id=access.get("id"))
            except Exception as e:
                print(f"Could not find team with id {access.get('id')} for credential '{name}'.")
                continue
            if role_name == "admin" and hasattr(cred_obj, "admin_role"):
                cred_obj.admin_role.team_set.add(team)
            elif role_name == "use" and hasattr(cred_obj, "use_role"):
                cred_obj.use_role.team_set.add(team)
            elif role_name == "read" and hasattr(cred_obj, "read_role"):
                cred_obj.read_role.team_set.add(team)

    # Re-establish related job templates.
    for jt_data in cred_data.get("related_job_templates", []):
        try:
            jt = JobTemplate.objects.get(id=jt_data.get("id"))
            jt.credentials.add(cred_obj)
        except Exception as e:
            print(f"Could not associate job template with id {jt_data.get('id')} to credential '{name}': {e}")
    return cred_obj

def import_credentials_from_file(filename):
    """
    Import credentials from a JSON file.
    Also prints a master list of credentials that were skipped due to duplicates.
    """
    try:
        with open(filename, "r") as f:
            creds_data = json.load(f)
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    imported_count = 0
    duplicates = []
    for cred_data in creds_data:
        if import_credential(cred_data, duplicates):
            imported_count += 1
    print(f"Imported {imported_count} credentials.")
    if duplicates:
        print("The following credentials were skipped (duplicates found):")
        for dup in duplicates:
            print(f"  - {dup}")

#
# Main menu loop
#
def main():
    while True:
        print("-------------------------------------------------")
        print("Main Menu:")
        print("  1) List all used Credential Types")
        print("  2) Decrypt ALL credentials")
        print("  3) Decrypt specific credentials")
        print("  4) Import credentials from file")
        print("  5) Exit")
        option = input("Enter option [1-5]: ").strip()

        if option == "1":
            types = list_used_credential_types()
            if not types:
                print("No credential types found.\n")
            else:
                print("\nUsed Credential Types:")
                for ct in types:
                    print(f"  {ct.id}) {ct.name}")
                print()
            input("Press Enter to return to the main menu...")

        elif option == "2":
            print("\nDecrypting ALL credentials...\n")
            decrypted = decrypt_all_credentials()
            output_results(decrypted)
            input("Press Enter to return to the main menu...")

        elif option == "3":
            creds = Credential.objects.all().order_by("id")
            if not creds:
                print("No credentials found.\n")
                input("Press Enter to return to the main menu...")
                continue
            print("\nAvailable Credentials:")
            for cred in creds:
                print(f"  {cred.id}) {cred.name} (Type: {cred.credential_type.name})")
            selection = input("Enter comma separated list of credential IDs to decrypt: ").strip()
            try:
                selected_ids = [int(x.strip()) for x in selection.split(",") if x.strip().isdigit()]
            except Exception as e:
                print(f"Error processing input: {e}")
                input("Press Enter to return to the main menu...")
                continue
            if not selected_ids:
                print("No valid credential IDs entered.")
                input("Press Enter to return to the main menu...")
                continue
            print("\nDecrypting selected credentials...\n")
            decrypted = decrypt_credentials_by_ids(selected_ids)
            output_results(decrypted)
            input("Press Enter to return to the main menu...")

        elif option == "4":
            filename = input("Enter the filename (with path) of the JSON file to import (e.g., /tmp/creds.json): ").strip()
            import_credentials_from_file(filename)
            input("Press Enter to return to the main menu...")

        elif option == "5":
            print("Exiting.")
            break

        else:
            print("Invalid option. Please try again.\n")

# Run the main menu unconditionally.
main()
