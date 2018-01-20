#!/usr/bin/env python3

import json
import yaml
import string
import secrets
import random
import os
import pprint
import rstr
import netaddr
import base64

def gen_pass():
    """
    Generates a password between 28 and 32 chars
    """
    length = random.randint(7,9)*4
    alphabet = string.ascii_letters + string.digits
    password = ''.join(secrets.choice(alphabet) for i in range(length))
    return password


def line_prepender(filename, line):
    with open(filename, 'r+') as f:
        content = f.read()
        f.seek(0, 0)
        f.write(line.rstrip('\r\n') + '\n' + content)


def gen_token():
    """ 
	Builds a token from regex [a-z0-9]{6}\.[a-z0-9]{16} 
	This token can be used for kubeadm init and join
    """
    token = rstr.xeger(r'[a-z0-9]{6}\.[a-z0-9]{16}')
    return token


def build_users(config):
    """ Build a user object """
    users = []
    # Generate the users
    for user in config['users']:
        newuser = {'name': 'USERNAME', 'gecos': 'Hypriot Pirate', 'sudo': 'ALL=(ALL) NOPASSWD:ALL', 'shell': '/bin/bash', 'groups': 'users,docker,video', 'plain_text_passwd': gen_pass(), 'lock_passwd': False, 'ssh_pwauth': True, 'chpasswd': {'expire': False}}
        newuser['name'] = user['name']

        # Remove admin pivs from non-admins
        if not user['admin']:
            newuser['sudo'] = ""
            newuser['groups'] = "users"
        users.append(newuser)
    return users


def build_network_config(config, node):
    writefiles = []
    # wlan
    if config['network']['wlan']['enabled']:
        # Create the interfaces file
        wlan0 = {}
        wlan0_content = """allow-hotplug wlan0\niface wlan0 inet dhcp\nwpa-conf /etc/wpa_supplicant/wpa_supplicant.conf\niface default inet dhcp\n"""
        wlan0['content'] = base64.b64encode(bytes(wlan0_content, "utf-8"))
        wlan0['path'] = r'/etc/network/interfaces.d/wlan0'
        writefiles.append(wlan0)
        
        # Create the wpa supplicant
        supplicant = {}
        supplicant['path'] = "/etc/wpa_supplicant/wpa_supplicant.conf"
        supplicant['encoding'] = "b64"
        supplicant_content = """ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev\nupdate_config=1\nnetwork={{\n  ssid="{0}"\n  psk="{1}"\n  proto=RSN\n  key_mgmt=WPA-PSK\n  pairwise=CCMP\n  auth_alg=OPEN\n  }}\n""".format(config['network']['wlan']['ssid'], config['network']['wlan']['psk'])
        supplicant['content'] = base64.b64encode(bytes(supplicant_content, "utf-8"))

        writefiles.append(supplicant)

    # Lan
    if config['network']['lan']['enabled']:
        network = netaddr.IPNetwork(config['network']['lan']['cidr'])
        netmask = network.netmask
        iplist = list(network)
        ip = iplist[node]
        gateway = iplist[254]

        eth0 = {}
        eth0['path'] = "/etc/network/interfaces.d/eth0"
        eth0['encoding'] = "b64"
        content = """auto eth0\niface eth0 inet static\n  address {0}\n  netmask {1}\n  gateway {2}\n""".format(ip,netmask,gateway)
        eth0['content'] = base64.b64encode(bytes(content,"utf-8"))
        writefiles.append(eth0)
    return writefiles
        

def build_base_commands():
    """ The base list of commands to run """
    cmds = []
    cmds.append(r'systemctl restart avahi-daemon')
    cmds.append(r'systemctl restart avahi-daemon')
    cmds.append(r'ifup wlan0')
    cmds.append(r'ifup eth0')
    cmds.append(r'apt-get update')
    cmds.append(r'apt-get upgrade')
    cmds.append(r'apt-get install -y curl jq git vim')
    cmds.append(r'curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg')
    cmds.append(r'curl -ks  https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add -')
    cmds.append(r'echo "deb http://apt.kubernetes.io/ kubernetes-xenial main" > /etc/apt/sources.list.d/kubernetes.list')
    cmds.append(r'apt-get update')
    cmds.append(r'apt-get install -y kubelet kubeadm kubectl')
    return cmds


def build_master(config, token):
    """ Bulds the master config"""
    master_config = {}

    # Fix the hostname
    master_config['hostname'] = "{0}-master".format(config['host-prefix'])

    # Add users
    master_config['users'] = build_users(config)

    # Add base run comands
    master_config['runcmd'] = build_base_commands()

    # Add the commands to init the master
    master_config['runcmd'].append(r'kubeadm init --token {0}'.format(token))
    master_config['runcmd'].append(r'mkdir /home/asuderma/.kube')
    master_config['runcmd'].append(r'cp /etc/kubernetes/admin.conf /home/asuderma/.kube/config')
    master_config['runcmd'].append(r'chown -R asuderma /home/asuderma/.kube')
    
    if config['kubeadm']['network'] == 'weavenet':
        master_config['runcmd'].append(r'export kubever=$(kubectl version | base64 | tr -d "\n")')
        master_config['runcmd'].append(r'kubectl apply -f "https://cloud.weave.works/k8s/net?k8s-version=$kubever"')
    
    # Add the other config options
    master_config['locale'] = "en_US.UTF-8"
    master_config['manage_etc_hosts'] = True
    
    # Add the network config
    master_config['write_files'] = build_network_config(config, 200)

    # Write the file
    filename = "{0}-master.yaml".format(config['host-prefix'])
    with open(filename, "w") as file:
        yaml.dump(master_config, file, default_flow_style=False)
    line_prepender(filename, "#cloud-config")
    return None


def build_node( config, token, node):
    """ Builds a node config """
    node_config = []

    #Set hostname
    node_config['hostname'] = "{0}-node{1}".format(config['host-prefix'], node)

    # Add users
    node_config['users'] = build_users(config)

    # Add base run commands
    node_config['runcmd'] = build_base_commands()

    # Join the cluster
    master_config['runcmd'].append(r'kubeadm join --token {0} --discovery-token-unsafe-skip-ca-verification'.format(token))

    # Add network config
    network_config['write_files'] = build_network_config(config, node)
    
    #Write the file
    filename = "{0}-node{1}.yaml".format(config['host-prefix'], node)
    with open(filename, "w") as file:
        yaml.dump(node_config, file, default_flow_style=False)
    line_prepender(filename, "#cloud-config")
    return None

if __name__ == "__main__":
    # Pull in the master config as dict
    user_config = yaml.load(open("cluster_config.yaml", "r" ))
    PP = pprint.PrettyPrinter(depth=6)
    my_token = gen_token()
    build_master(user_config, my_token)

