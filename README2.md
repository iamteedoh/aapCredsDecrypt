# AWX/AAP Credential Management Script

This script provides utilities for managing credentials within an AWX (Ansible Tower) or AAP (Ansible Automation Platform) environment. It allows you to list used credential types, decrypt and export credential details (including sensitive fields), and import credentials from a JSON file.  It's designed to be run within the AWX/AAP Python environment, typically using `awx-manage shell_plus`.

## Purpose

The primary goals of this script are:

1.  **Credential Auditing:**  Provide a way to inspect *all* credential details, including encrypted fields, in a human-readable format. This is crucial for security audits, troubleshooting, and understanding how credentials are being used.
2.  **Credential Migration:** Facilitate the migration of credentials between AWX/AAP instances by providing export and import capabilities.
3.  **Credential Type Discovery:** List all *actively used* credential types within the AWX/AAP instance.
4. **Credential-Job Template Mapping:** List all Job Templates and Projects associated with a credential, this includes direct and indirect relations.
5. **Credential-Access Mapping:** Show all users and teams that have access to a specific credential.

## Prerequisites

*   **AWX/AAP Environment:** This script *must* be run within a properly configured AWX or AAP environment.  It relies on Django models and utilities specific to these platforms. The recommended way to run it is via the `awx-manage shell_plus` command.
*   **Administrative Privileges:** You need to be logged in as a user with sufficient privileges to access and modify credentials, organizations, teams, users, and job templates.  Typically, this means being a system administrator.
*   **Python 3:** The script is intended for Python 3.
*   **`awx` package**: The `awx` package is required, and should be available inside `awx-manage shell_plus`

## How to Run

1.  **Access the AWX/AAP Shell:**  Open a terminal on your AWX/AAP server (or within the appropriate container if running in a containerized environment) and run:

    ```bash
    awx-manage shell_plus
    ```

2.  **Execute the Script:**  Within the `shell_plus` environment, execute the Python script.  Replace `/path/to/script.py` with the actual path to the script file:

    ```python
    exec(open("/path/to/script.py").read())
    ```
    Alternatively you could copy and paste the script directly into `shell_plus`.

3.  **Follow the Menu:** The script will present a text-based menu with options to list credential types, decrypt credentials, or import credentials.

## Script Breakdown

The script is organized into several functions, each performing a specific task:

### 1. Imports and Setup

```python
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
    print("        For example, run 'awx-manage shell_plus' then 'exec(open(\"/path/to/script.py\").read())'")
    sys.exit(1)

print("DEBUG: Past the try/except. About to define functions.")

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

* `#!/usr/bin/env python`: Shebang line, indicating the script should run with Python's default environment version.
* `import sys, json, datetime`: Imports standard Python libraries for system interaction, JSON handling, and date/time manipulation.
* `try...except ImportError`: This block attempts to import necessary modules from the `awx` package. If these imports fail, it means the script is not being run in the correct AWX/AAP environment, and an error message is printed, followed by exiting the script.
* `from awx.main.models import ...`: Imports specific Django models representing AWX/AAP objects (Credentials, CredentialTypes, Organizations, etc.).
* `from awx.main.utils import decrypt_field`: Imports the crucial function for decrypting encrypted credential fields.
* `from django.db.models import Q`: Import used to constructed complex queries for the database.
* `SECRET_FIELDS`: A list of field names known to contain encrypted data within AWX/AAP credential objects.

2. `list_used_credential_types()`

```python
def list_used_credential_types():
    """
    Return a queryset of CredentialTypes that are actively used by at least one Credential.
    """
    used_ct_ids = Credential.objects.values_list("credential_type_id", flat=True).distinct()
    return CredentialType.objects.filter(id__in=used_ct_ids)
```

* This function identifies and returns a list of `CredentialType` objects that are currently in use (i.e., associated with at least one `Credential`).
* `Credential.objects.values_list("credential_type_id", flat=True).distinct()`: This efficiently retrieves a list of unique `credential_type_id` values from all existing `Credential` objects. `flat=True` ensures a simple list of IDs is returned, rather than a list of tuples.
* `CredentialType.objects.filter(id__in=used_ct_ids)`: This filters the `CredentialType` objects, returning only those whose IDs are present in the `used_ct_ids` list.

3. `get_teams_from_role()`

```python
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
```

* This function takes a `Role` object as input and returns a list of `Team` objects associated with that role. It's designed to handle variations in how roles and teams are related across different versions of AWX/AAP.
* `hasattr(role, 'team_set')` / `hasattr(role, 'teams')`: Checks for the existence of attributes that might link a role to teams, adapting to different AWX/AAP model structures.
* `role._meta.related_objects`: If the direct attributes aren't found, this iterates through the role's related objects to find a relationship to the `Team` model.
* `if not teams`: If there is not team associated with the role a warning is printed to the console.

4. `decrypt_single_credential(cred)`

```python
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
```

* This is the core function for decrypting a single `Credential` object. It takes a `Credential` object as input and returns a dictionary containing:
    ** Basic credential information (ID, name, type, creation/modification timestamps, organization).
    ** A list of users and teams with access to the credential (the "access list").
    ** A list of related Job Templates.
    ** A list of input fields, including decrypted values for sensitive fields.
* `ct = cred.credential_type`: Retrieves the `CredentialType` associated with the credential.
* `field_defs = {}`: Initializes dict to store input field information (id, label).
* The `try...except` block gets credential labels from the credential type's inputs.
* `cred_info = { ... }`: Initializes the dictionary that will hold the decrypted credential data.
* `if cred.organization:`: Populates organization details if the credential is part of an organization.
* `for role_attr in ['admin_role', 'use_role', 'read_role']`: Iterates through the possible role attributes (admin, use, read) associated with a credential.
    ** `role_obj = getattr(cred, role_attr, None)`: Gets the `Role` object associated with the current role attribute (e.g., `cred.admin_role`).
    ** `for user in role_obj.members.all()`: Adds users with this role to the `access_list`.
    ** `for team in get_teams_from_role(role_obj)`: Adds teams with this role to the `access_list`.
* `for jt in JobTemplate.objects.filter(credentials=cred)`: Adds directly related `JobTemplate` objects to the `related_job_templates` list.
* The next block handles indirect job template relations.
    ** `filter_query = Q(credential_id=cred.id)`: Starts building a query to find related `Project` objects.
    ** `if 'scm_credential' in [f.name for f in Project._meta.get_fields()]`: Checks if the project has the scm_credential.
    ** `filter_query |= Q(scm_credential_id=cred.id)`: Adds a clause to the query to include projects where the credential is used as the SCM credential (if applicable).
    ** `for proj in Project.objects.filter(filter_query)`: Iterates through projects related to the credential.
        ** `for jt in JobTemplate.objects.filter(project_id=proj.id)`: Adds job templates associated with the found projects to `related_job_templates`.
* `for key, value in cred.inputs.items()`: Iterates through the credential's input fields.
    ** if key in SECRET_FIELDS: Checks if the current field is in the `SECRET_FIELDS` list.
        ** `actual_value = decrypt_field(cred, key)`: Decrypts the field value using the `decrypt_field` function.
        ** `except Exception as e`: Handles potential errors during decryption.
    ** `else: actual_value = value`: If the field is not a secret field, the value is used directly.
* `return cred_info`: Returns the dictionary containing all extracted credential information.

5. `decrypt_credentials_by_ids(ids_list)`

```python
def decrypt_credentials_by_ids(ids_list):
    """
    Given a list of credential IDs, decrypt and return their details.
    """
    creds = Credential.objects.filter(id__in=ids_list)
    results = []
    for cred in creds:
        results.append(decrypt_single_credential(cred))
    return results
```

* This function takes a list of credential IDs, decrypts each corresponding credential, and returns a list of dictionaries containing the decrypted data.
* `creds = Credential.objects.filter(id__in=ids_list)`: Retrieves `Credential` objects matching the provided IDs.
* `results = []`: Initializes a list to store results.
* `for cred in creds`: Iterates over each found `Credential`
* `results.append(decrypt_single_credential(cred))`: Appends result of `decrypt_single_credential`

6. `decrypt_all_credentials()`

```python
def decrypt_all_credentials():
    """
    Decrypt and return details for all credentials.
    """
    creds = Credential.objects.all()
    results = []
    for cred in creds:
        results.append(decrypt_single_credential(cred))
    return results
```

* This function decrypts all credentials in the AWX/AAP instance and returns a list of dictionaries containing the decrypted data.
* Very similar to `decrypt_credentials_by_ids()`, but retrieves all credentials using `.all()`.

7. `output_results(decrypted)`

```python
def output_results(decrypted):
    """
    Prompt the user for output options and display the decrypted credentials.
    """
    if decrypted:
        for cred in decrypted:
            unique_jts = {tuple(sorted(d.items())) for d in cred['related_job_templates']}
            cred['related_job_templates'] = [dict(t) for t in unique_jts]

        output_json
```

