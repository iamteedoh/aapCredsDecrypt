# Playbook Version of aapCredsManagement.py

## Notes:

There are several playbooks contained in `individualPlaybooks` folder. However, the true and final playbook to work with would be the one called `aapCredsManagementPlaybook.yml`. This playbook is the closest one to getting the playbook to mimic the python script called `aapCredsManagement.py`. The issue is that the export portion of the playbook does not do a good job decrypting the credentials. That is something that still needs to be worked on.

The other playbooks, which are:
* import_all_credentials_ssh.yml
* import_single_credential_ssh.yml
* reestablish_jt_associations_ssh.yml
* reestablish_team_access_ssh.yml
* reestablish_user_access_ssh.yml

...are just a breakdown of the same `aapCredsManagementPlaybook.yml`. It's just broken down into smaller chunks and I've placed them in the sub-directory called `individualPlaybooks`. With that said, you can continue to modify these individual playbooks to get this export to work OR you can focus on doing it all within one playbook, which is the one called `aapCredsManagementPlaybook.yml`.

The same `inventory.yml` file can be used for the `individualPlaybooks` files or the `aapCredsManagementPlaybook.yml`
