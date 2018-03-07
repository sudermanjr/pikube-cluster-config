#!/usr/bin/env python3

import json
import yaml
import string
import secrets
import random
import os
import crypt
import pprint
import rstr
import netaddr
import base64
import logging

def gen_pass():
    """
    Generates a password between 35 and 45 chars
    """
    length = random.randint(7,9)*5
    alphabet = string.ascii_letters + string.digits
    password = ''.join(secrets.choice(alphabet) for i in range(length))
    return password


def sha512_crypt(password, salt=None, rounds=None):
    if salt is None:
        rand = random.SystemRandom()
        salt = ''.join([rand.choice(string.ascii_letters + string.digits)
                        for _ in range(8)])

    prefix = '$6$'
    if rounds is not None:
        rounds = max(1000, min(999999999, rounds or 5000))
        prefix += 'rounds={0}$'.format(rounds)
    return crypt.crypt(password, prefix + salt)


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
    LOG.debug('Generating Token')
    token = rstr.xeger(r'[a-z0-9]{6}\.[a-z0-9]{16}')
    LOG.debug("Token: {0}".format(token))
    return token


def build_users(config):
    """ Build a user object """
    users = []

    # Generate the users
    for user in config['users']:
        newuser = {}
        newuser['gecos'] = user['name']
        newuser['name'] = user['name']
        newuser['shell'] = '/bin/bash'
        passwd = gen_pass()
        newuser['passwd'] =  sha512_crypt(passwd, None, 4096)

        newuser['lock_passwd'] = False
        newuser['chpasswd'] = {'expire': False}

        if 'sshPublicKey' in user:
            # Set their key and disable pw auth
            newuser['ssh_authorized_keys'] = [user['sshPublicKey']]
            newuser['ssh_pwauth'] = False
        else:
            # Log the password so that we can find it later, and enable pwauth
            newuser['ssh_pwauth'] = True
        LOG.info('The password for {0} will be {1}'.format(user['name'], passwd))
        # Give admins some stuff
        if user['admin']:
            newuser['sudo'] = 'ALL=(ALL) NOPASSWD:ALL'
            newuser['groups'] = "users,docker,video"
        else:
            newuser['groups'] = "users"
        users.append(newuser)
    return users


def configure_alfred(node):
    """
        Adds the systemd unit file to start
    """
    alfred_unit = {}
    alfred_unit_content = """[Unit]\nDescription=alfred\n\n[Service]\nExecStart=/usr/local/sbin/alfred -i bat0 -m\nRestart=always\nRestartSec=10s\n\n[Install]\nWantedBy=multi-user.target"""

    alfred_unit['content'] = base64.b64encode(bytes(alfred_unit_content, "utf-8"))
    alfred_unit['encoding'] = "b64"
    alfred_unit['path'] = r'/etc/systemd/system/alfred.service'

    return alfred_unit

def build_network_config(config, node):
    writefiles = []
    # wlan
    if config['network']['wlan']['enabled']:
        # Create the interfaces file
        wlan0 = {}
        wlan0_content = """allow-hotplug wlan0\niface wlan0 inet dhcp\nwpa-conf /etc/wpa_supplicant/wpa_supplicant.conf\niface default inet dhcp\n"""
        wlan0['content'] = base64.b64encode(bytes(wlan0_content, "utf-8"))
        wlan0['encoding'] = "b64"
        wlan0['path'] = r'/etc/network/interfaces.d/wlan0'
        writefiles.append(wlan0)

        # Create the wpa supplicant
        supplicant = {}
        supplicant['path'] = "/etc/wpa_supplicant/wpa_supplicant.conf"
        supplicant['encoding'] = "b64"
        supplicant_content = """ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev\nupdate_config=1\nnetwork={{\n  ssid="{0}"\n  psk="{1}"\n  proto=RSN\n  key_mgmt=WPA-PSK\n  pairwise=CCMP\n  auth_alg=OPEN\n  }}\n""".format(config['network']['wlan']['ssid'], config['network']['wlan']['psk'])
        supplicant['content'] = base64.b64encode(bytes(supplicant_content, "utf-8"))

        writefiles.append(supplicant)

    # lan
    if config['network']['lan']['enabled']:
        eth0 = {}
        eth0['path'] = "/etc/network/interfaces.d/eth0"
        eth0['encoding'] = "b64"

        if config['network']['lan']['dhcp']:
            LOG.debug('Lan DHCP Selected')
            content = """auto eth0\nallow-hotplug eth0\niface eth0 inet dhcp\n"""
        else:
            LOG.debug('Lan Manual Configuration')
            network = netaddr.IPNetwork(config['network']['lan']['cidr'])
            netmask = network.netmask
            iplist = list(network)
            ip = iplist[node]
            gateway = iplist[254]
            content = """auto eth0\niface eth0 inet static\n  address {0}\n  netmask {1}\n  gateway {2}\n""".format(ip,netmask,gateway)

        eth0['content'] = base64.b64encode(bytes(content,"utf-8"))
        writefiles.append(eth0)
    return writefiles


def build_base_commands(config):
    """ The base list of commands to run """
    cmds = []
    cmds.append(r'systemctl restart avahi-daemon')
    cmds.append(r'ifdown wlan0')
    cmds.append(r'ifdown eth0')
    cmds.append(r'service network restart')
    cmds.append(r'ifup wlan0')
    cmds.append(r'ifup eth0')
    cmds.append(r'apt-get update')
    cmds.append(r'apt-get upgrade')
    cmds.append(r'apt-get install -y curl jq git vim dnsutils make gcc')
    cmds.append(r'curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg')
    cmds.append(r'curl -ks  https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add -')
    cmds.append(r'echo "deb http://apt.kubernetes.io/ kubernetes-xenial main" > /etc/apt/sources.list.d/kubernetes.list')
    cmds.append(r'apt-get update')
    cmds.append(r'apt-get install -y kubelet kubeadm kubectl')

    # Add batman specific commands if it is enabled
    if config['network']['batman']['enabled']:
        # Install batman adv deps
        cmds.append(r'apt-get install -y libnl-3-dev libnl-genl-3-dev libcap-dev libgps-dev')

        # Get batctl and build it
        cmds.append(r'git clone https://git.open-mesh.org/batctl.git')
        cmds.append(r'cd batctl && make install')

        # Get and build alfred, then start the service
        cmds.append(r'cd && git clone https://git.open-mesh.org/alfred.git')
        cmds.append(r'cd alfred && make install')
        cmds.append(r'systemctl enable alfred')
        cmds.append(r'systemctl start alfred')

        # Enable the batman adv kernel module
        cmds.append(r'modprobe batman-adv')

    return cmds


def build_master(config, token):
    """ Bulds the master config"""
    LOG.debug('Building master config')
    master_config = {}

    # Fix the hostname
    master_config['hostname'] = "{0}-master".format(config['host-prefix'])

    # Add users
    master_config['users'] = build_users(config)

    # Add base run comands
    master_config['runcmd'] = build_base_commands(config)

    # Add the commands to init the master
    master_config['runcmd'].append(r'kubeadm init --token {0} --feature-gates=SelfHosting={1}'.format(token, config['kubeadm']['selfHosted']))
    master_config['runcmd'].append(r'export KUBECONFIG=/etc/kubernetes/admin.conf')
    if config['kubeadm']['network'] == 'weavenet':
        master_config['runcmd'].append(r'export kubever=$(kubectl version | base64 | tr -d "\n")')
        master_config['runcmd'].append(r'kubectl apply -f "https://cloud.weave.works/k8s/net?k8s-version=$kubever"')
        master_config['runcmd'].append(r'kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/master/src/deploy/alternative/kubernetes-dashboard-arm.yaml')

    # Add the other config options
    master_config['locale'] = "en_US.UTF-8"
    master_config['manage_etc_hosts'] = True

    # Add the network config
    master_config['write_files'] = build_network_config(config, 200)

    # If batman is selected, then add it to the writefiles
    master_config['write_files'].append(configure_alfred(200))

    # Write the file
    filename = "{0}-master.yaml".format(config['host-prefix'])
    with open(filename, "w") as file:
        yaml.dump(master_config, file, default_flow_style=False)
    line_prepender(filename, "#cloud-config")
    return None


def build_node( config, token, node):
    """ Builds a node config """
    LOG.debug('Building Node Configs')
    node_config = {}

    #Set hostname
    node_config['hostname'] = "{0}-node{1}".format(config['host-prefix'], node)

    # Add users
    node_config['users'] = build_users(config)

    # Add base run commands
    node_config['runcmd'] = build_base_commands(config)

    # Join the cluster
    node_config['runcmd'].append(r'kubeadm join --token {0} {1}-master:6443 --discovery-token-unsafe-skip-ca-verification'.format(token, config['host-prefix']))

    # Add network config
    node_config['write_files'] = build_network_config(config, node)

    # If batman is selected, then add it to the writefiles
    node_config['write_files'].append(configure_alfred(node))

    #Write the file
    filename = "{0}-node{1}.yaml".format(config['host-prefix'], node)
    with open(filename, "w") as file:
        yaml.dump(node_config, file, default_flow_style=False)
    line_prepender(filename, "#cloud-config")
    return None


def build_all_nodes(config, token):
    count = 1
    while (count <= config['node_count']):
        LOG.debug('Generating node: {0}'.format(count))
        build_node(config, token, count)

        count += 1
    return None

def build_configs():
    """ Build all the configs using the user cluster_config.yaml """
    # Pull in the master config as dict
    user_config = yaml.load(open("cluster_config.yaml", "r" ))
    my_token = ""
    if 'token' in user_config['kubeadm']:
        my_token = user_config['kubeadm']['token']
    else:
        my_token = gen_token()

    LOG.info('Using Token: {0}'.format(my_token))
    build_master(user_config, my_token)
    build_all_nodes(user_config, my_token)
    LOG.info('Configs are generated')


if __name__ == "__main__":
    # setup loggig
    logging.basicConfig( format="%(asctime)s %(levelname)7s  %(funcName)s %(message)s")
    LOG = logging.getLogger("pikube")
    LOG.setLevel(logging.DEBUG)
    PP = pprint.PrettyPrinter(depth=6)

    build_configs()
