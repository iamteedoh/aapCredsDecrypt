# AWX/AAP Credential Decrypt & Import Script

This script is designed for AWX/AAP environments to facilitate the decryption and import of credentials. It provides an interactive menu-based interface to:
- List all used Credential Types.
- Decrypt all credentials or selected ones.
- Import credentials from a JSON file.

The script leverages AWX/AAP’s Django ORM and models, including `Credential`, `CredentialType`, `Organization`, `Project`, `JobTemplate`, `Team`, `Role`, and `User`, along with utility functions like `decrypt_field`.

---

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation and Setup](#installation-and-setup)
- [Usage Instructions](#usage-instructions)
- [Function Details](#function-details)
  - [list_used_credential_types](#list_used_credential_types)
  - [get_teams_from_role](#get_teams_from_role)
  - [decrypt_single_credential](#decrypt_single_credential)
  - [decrypt_credentials_by_ids](#decrypt_credentials_by_ids)
  - [decrypt_all_credentials](#decrypt_all_credentials)
  - [output_results](#output_results)
  - [import_credential](#import_credential)
  - [import_credentials_from_file](#import_credentials_from_file)
  - [main](#main)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## Introduction

This script is a utility to manage AWX/AAP credentials by decrypting sensitive fields and importing credentials from a JSON file. It is meant to be executed within an AWX/AAP environment where all the necessary Django models and AWX-specific utilities are available.

---

## Features

- **List Credential Types:** Identify which credential types are currently in use.
- **Decrypt Credentials:** Decrypt secret fields (like passwords and keys) for:
  - All stored credentials.
  - Specific credentials chosen by their IDs.
- **Import Credentials:** Import credentials back into AWX/AAP from a JSON file, with:
  - Duplicate checks.
  - Restoration of role memberships and job template associations.
- **Interactive Output Options:** Choose to display results on screen, export to a file, or both.

---

## Prerequisites

- **AWX/AAP Environment:**  
  This script must run within the AWX/AAP environment because it requires access to AWX-specific Django models and utilities.  
  
  _Tip:_ If running from within `awx-manage`, as an elevated user, such as root, run `awx-manage shell_plus` and execute the script with:
  ```
  exec(open("/path/to/aapCredsManagement.py").read())
  ```

- **Python:**  
  A compatible Python version (3.x+) installed within the AWX/AAP environment.
  
- **AWX/AAP Modules:**  
  Ensure that the following modules are available:
  - `awx.main.models` (includes Credential, CredentialType, Organization, Project, JobTemplate, Team, Role, User)
  - `awx.main.utils` (provides `decrypt_field`)

  **Note:** This is done via the `import` of modules within the Python script

---

## Installation and Setup

1. **Import the Script:**  
   Save the script as `aapCredsManagement.py` or with whatever name you prefer onto your AWX/AAP server where the required Python environment is active. This is typically your `controller node`.

2. **Apply Appropriate Permissions:**  
   Optionally, make the script executable, if not by default:
   ```
   chmod +x aapCredsManagement.py
   ```

3. **Environment Verification:**  
   Confirm you have access to AWX models by running an interactive shell with:
   ```
   awx-manage shell_plus
   ```

---

## Usage Instructions

1. **Start the Script:**  
   Run the script in the AWX/AAP environment:
   ```
   ./aapCredsManagement.py
   ```
   Or from an AWX shell (recommended due to interactivity):
   ```
   exec(open("/path/to/aapCredsManagement.py").read())
   ```

2. **Interactive Main Menu:**  
   Upon execution, the script displays a menu with options:
   - **1:** List all used Credential Types.
   - **2:** Decrypt ALL credentials.
   - **3:** Decrypt specific credentials by entering a comma-separated list of Credential IDs.
   - **4:** Import credentials from a JSON file.
   - **5:** Exit.

3. **Output Options (for Decryption):**  
   After decryption, you will be prompted to choose between:
   - Printing the decrypted data to standard output.
   - Saving the decrypted data to a file.
   - Both, printing and saving.

4. **Import Process:**  
   When importing, the script checks for duplicates (credentials with the same name, type, and organization) and logs those that are skipped.

---

## Function Details

### list_used_credential_types
- **Purpose:**  
  Retrieves a list of `CredentialType` objects that are actively used by at least one `Credential`.
- **Implementation:**  
  It collects distinct credential type IDs from the `Credential` objects and filters the `CredentialType` queryset accordingly.

### get_teams_from_role
- **Purpose:**  
  Given a `Role` object, returns the associated list of `Team` objects.
- **Implementation:**  
  Handles differences across AWX/AAP versions by checking for attributes like `team_set` or `teams`, or by iterating over the role’s related objects.
    - If the list of `teams` is empty, it prints a warning message **"WARNING: Could not find related teams for role: ..."**

### decrypt_single_credential
- **Purpose:**  
  Decrypts a single credential and builds a detailed dictionary with:
  - Credential metadata (ID, name, type, creation/modification dates)
  - Organization details
  - Access list (users and teams)
  - Related job templates
  - Decrypted input fields
- **Implementation:**  
  Iterates through each field, decrypting secret fields using `decrypt_field` while preserving the original value for non-secret fields.

### decrypt_credentials_by_ids
- **Purpose:**  
  Fetches and decrypts credentials based on a list of provided Credential IDs.
- **Implementation:**  
  Utilizes Django’s ORM to filter credentials by IDs and then applies `decrypt_single_credential` for each.

### decrypt_all_credentials
- **Purpose:**  
  Decrypts every credential stored in the AWX system.
- **Implementation:**  
  Fetches all credentials using the ORM and processes each with `decrypt_single_credential`.

### output_results
- **Purpose:**  
  Provides options for outputting decrypted credentials:
  - Standard output (console)
  - Saving to a JSON file
  - Both
- **Implementation:**  
  Converts the output to formatted JSON and prompts the user for their preferred method of output.

### import_credential
- **Purpose:**  
  Imports a single credential from a dictionary derived from a JSON export.
- **Implementation:**  
  - Validates existence of the corresponding `Name`, `CredentialType`, and the `Organization`.
  - Checks for an existing credential to avoid duplicates.
  - Converts the “fields” list into an “inputs” dictionary.
  - Creates the new `Credential` object.
  - Restores role memberships and associations with job templates.

### import_credentials_from_file
- **Purpose:**  
  Imports multiple credentials from a JSON file.
- **Implementation:**  
  - Reads JSON data from the provided filename.
  - Iterates over each credential’s data, invoking `import_credential`.
  - Summarizes the number of credentials imported and lists duplicates that were skipped.

### main
- **Purpose:**  
  Acts as the primary control loop offering an interactive menu.
- **Implementation:**  
  - Displays a menu with options to list credential types, decrypt credentials (all or specific), import credentials, or exit.
  - Processes user input and calls the corresponding functions.
  - Loops continuously until the user chooses to exit the program.

---

## Troubleshooting

- **Import Errors:**  
  If you see errors regarding the AWX/AAP models (such as missing imports), ensure you are running the script within the AWX/AAP environment.
  
- **Decryption Failures:**  
  If decryption of a specific field fails, the error is captured and the field value will be set to `None`. Check the output in the console where the interactivity of the program is occurring.

- **File I/O Issues:**  
  Ensure the file paths provided for saving or importing JSON data are accessible and you have the necessary permissions.

---

## Contributing

Contributions and improvements to the script are welcome. When submitting changes:
- Ensure compatibility with the AWX/AAP environment.
- Update this README accordingly.
- Provide clear commit messages and document any new features, please. This is VERY IMPORTANT!!!

---

## License

This script is provided "as-is" without any warranty. Users are free to use, modify, and distribute the script, subject to any AWX/AAP licensing restrictions.

---

## Playbook Notes

This task below should be added to the main playbook, which is what will call the appropriate playbooks to import credentials

```
- name: Import ALL credentials from JSON (No Script)
  ansible.builtin.import_playbook: import_all_credentials.yml  # Correct playbook
  vars:
    credential_file: "/path/to/your/creds.json"  # Specify the file!
```

However, to test outside of the main playbook, we can add the following as a temporary "main" playbook:

```
---

- name: Main Playbook
  hosts: localhost
  gather_facts: false
  become: false

  tasks:
    - name: Import ALL credentials from JSON (No Script)
      ansible.builtin.import_playbook: import_all_credentials.yml  # Correct playbook
      vars:
        credential_file: "/path/to/your/creds.json"  # Specify the file!
```
