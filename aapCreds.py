#!/usr/bin/env python
"""
AWX/AAP Credential Export/Import Management Command

Place this file under:
    awx/main/management/commands/aapCreds.py

Usage:
  Interactive mode:
      awx-manage aapCreds
  Non-interactive mode:
      awx-manage aapCreds --quiet --export --export-file=/tmp/creds.json
      awx-manage aapCreds --quiet --import --import-file=/tmp/creds.json
      etc.
"""

import sys
import json
import os
import subprocess
import tempfile

from django.core.management.base import BaseCommand
from django.db.models import Q

# AWX/AAP specific imports
from awx.main.models import (
    Credential, CredentialType, Organization, Project,
    JobTemplate, Team, Role, User
)
from awx.main.utils import decrypt_field

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
