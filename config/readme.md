# Ansible depencency install

Ansible can be used to install all dependencies for the DNS bruteforcer project.

1. Add all hosts you want to configure in your ssh config file (`~/.ssh/config`)
2. Copy the hosts_example.yml file and add the hostnames to configure
3. run ansible with `ansible-playbook master-playbook.yml -i hosts_example.yml`