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


def configure_alfred():
    """
        Adds the systemd unit file to start
    """
    alfred_unit = {}
    alfred_unit_content = """[Unit]\nDescription=alfred\n\n[Service]\nExecStart=/usr/local/sbin/alfred -i bat0 -m\nRestart=always\nRestartSec=10s\n\n[Install]\nWantedBy=multi-user.target"""

    alfred_unit['content'] = base64.b64encode(bytes(alfred_unit_content, "utf-8"))
    alfred_unit['encoding'] = "b64"
    alfred_unit['path'] = r'/etc/systemd/system/alfred.service'

    return alfred_unit


def configure_batvis():
    """
        Adds the batman vis service file
    """
    batvis_unit = {}
    batvis_content = """
[Unit]
Description=batadv-vis

[Service]
ExecStart=/usr/local/sbin/batadv-vis -i bat0 -s
Restart=always
RestartSec=10s

[Install]
WantedBy=multi-user.target
"""
    batvis_unit['content'] = base64.b64encode(bytes(batvis_content, "utf-8"))
    batvis_unit['encoding'] = "b64"
    batvis_unit['path'] = r'/etc/systemd/system/batadv-vis.service'

    return batvis_unit


def dhcp_default():
    """
    Creates the /etc/default/isc-dhcp-server file
    """
    dhcp_default = {}
    dhcp_default_content = """INTERFACES='bat0'"""
    dhcp_default['path'] = r'/etc/default/isc-dhcp-server'
    dhcp_default['encoding'] = "b64"
    dhcp_default['content'] = base64.b64encode(bytes(dhcp_default_content, "utf-8"))
    return dhcp_default

def configure_dhcp():
    """
        Creates a dhcp config file
    """
    dhcp_config = {}
    dhcp_config_content = """
ddns-update-style none;
default-lease-time 600;
max-lease-time 7200;
option domain-name-servers 84.200.69.80, 84.200.70.40;
option domain-name "pikube.local";
authorative;
log-facility local7;

subnet 10.12.29.0 netmask 255.255.255.0 {
  range 10.12.29.10 10.12.29.100;
}
"""

    dhcp_config['path'] = r'/etc/dhcp/dhcpd.conf'
    dhcp_config['encoding'] = "b64"
    dhcp_config['content'] = base64.b64encode(bytes(dhcp_config_content, "utf-8"))
    return dhcp_config


def build_network_config(config, node):
    writefiles = []

    # wlan - if mesh is not active
    if config['network']['wlan']['enabled']:
        wlan0 = {}
        if not config['network']['wlan']['mesh']['enabled']:
            LOG.debug("Configuring regular wireless connection")

            # Create the interfaces file
            wlan0_content = """allow-hotplug wlan0\niface wlan0 inet dhcp\nwpa-conf /etc/wpa_supplicant/wpa_supplicant.conf\niface default inet dhcp\n"""

            # Create the wpa supplicant
            supplicant = {}
            supplicant['path'] = "/etc/wpa_supplicant/wpa_supplicant.conf"
            supplicant['encoding'] = "b64"
            supplicant_content = """
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1
network={{
  ssid="{0}"
  psk="{1}"
  proto=RSN
  key_mgmt=WPA-PSK
  pairwise=CCMP
  auth_alg=OPEN
  }}
""".format(config['network']['wlan']['ssid'], config['network']['wlan']['psk'])
            supplicant['content'] = base64.b64encode(bytes(supplicant_content, "utf-8"))
            writefiles.append(supplicant)
        else:
            LOG.debug("Configuring wifi for mesh networking")
            wlan0_content = """
auto wlan0
iface wlan0 inet6 manual
  wireless-channel {1}
  wireless-essid {0}
  wireless-mode ad-hoc
  wireless-ap 02:12:34:56:78:9A
  pre-up /sbin/ifconfig wlan0 mtu 1532
""".format(config['network']['wlan']['mesh']['name'], config['network']['wlan']['mesh']['channel'])

            bat0 = {}
            if node is 200: # Master node static
                bat0_content = """
auto bat0
iface bat0 inet6 auto
  pre-up /usr/local/sbin/batctl if add wlan0
  pre-up /usr/local/sbin/batctl gw_mode server
 
iface bat0 inet static
  address 10.12.29.254
  netmask 255.255.255.0
  gateway 10.12.29.254
"""
            else: # Other nodes DHCP
                bat0_content = """
auto bat0
iface bat0 inet6 auto
  pre-up /usr/local/sbin/batctl if add wlan0
  pre-up /usr/local/sbin/batctl gw_mode client

iface bat0 inet dhcp 
"""
            bat0['content'] = base64.b64encode(bytes(bat0_content, "utf-8"))
            bat0['path'] = r'/etc/network/interfaces.d/bat0'
            bat0['encoding'] = "b64"
            writefiles.append(bat0)


        wlan0['content'] = base64.b64encode(bytes(wlan0_content, "utf-8"))
        wlan0['encoding'] = "b64"
        wlan0['path'] = r'/etc/network/interfaces.d/wlan0'
        writefiles.append(wlan0)

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
            content = """
auto eth0
iface eth0 inet static
  address {0}
  netmask {1}
  gateway {2}
""".format(ip,netmask,gateway)

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
    cmds.append(r'apt-get install -o Dpkg::Options::="--force-confold" --force-yes -y curl jq git vim dnsutils')
    cmds.append(r'curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg')
    cmds.append(r'curl -ks  https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add -')
    cmds.append(r'echo "deb http://apt.kubernetes.io/ kubernetes-xenial main" > /etc/apt/sources.list.d/kubernetes.list')
    cmds.append(r'apt-get update')
    cmds.append(r'apt-get install -o Dpkg::Options::="--force-confold" --force-yes -y kubelet kubeadm kubectl')

    # Add batman specific commands if it is enabled
    if config['network']['wlan']['mesh']['enabled']:
        # Install batman adv deps
        cmds.append(r'apt-get install -o Dpkg::Options::="--force-confold" --force-yes -y libnl-3-dev libnl-genl-3-dev libcap-dev libgps-dev make gcc')

        # Get batctl and build it
        cmds.append(r'git clone https://git.open-mesh.org/batctl.git')
        cmds.append(r'cd batctl && make install')

#        # Download the batman adv kernel module
#        cmds.append(r'curl -o batman-adv-2018.0.tar.gz https://downloads.open-mesh.org/batman/stable/sources/batman-adv/batman-adv-2018.0.tar.gz')
#        cmds.append(r'tar -zxvf batman-adv-2018.0.tar.gz')

        # Enable the batman adv kernel module
        cmds.append(r'modprobe batman-adv')
        cmds.append(r'echo "batman-adv" >> /etc/modules')

        # Start the interfaces for the mesh
        cmds.append(r'ip link set up dev wlan0')
        cmds.append(r'ifup bat0')
        cmds.append(r'ip link set up dev bat0')

        # Get and build alfred, then start the service
        cmds.append(r'cd && git clone https://git.open-mesh.org/alfred.git')
        cmds.append(r'cd alfred && make install')
        cmds.append(r'systemctl enable alfred')
        cmds.append(r'systemctl start alfred')

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

    # Set the master interface
    if config['network']['wlan']['mesh']['enabled']:
        master_iface = "$(ip addr show bat0 | grep -Po 'inet \K[\d.]+')"
        LOG.debug("Used mesh configuration for master_iface")
    else:
        master_iface = '0.0.0.0'
        LOG.debug("Set master_iface to 0.0.0.0")

    # Add the commands to init the master
    master_config['runcmd'].append(r'apt-get install -o Dpkg::Options::="--force-confold" --force-yes -y isc-dhcp-server')
    master_config['runcmd'].append(r'kubeadm init --token {0} --feature-gates=SelfHosting={1} --apiserver-advertise-address {2}'.format(token, config['kubeadm']['selfHosted'], master_iface.strip()))
    master_config['runcmd'].append(r'export KUBECONFIG=/etc/kubernetes/admin.conf')
    if config['kubeadm']['network'] == 'weavenet':
        master_config['runcmd'].append(r'export kubever=$(kubectl version | base64 | tr -d "\n")')
        master_config['runcmd'].append(r'kubectl apply -f "https://cloud.weave.works/k8s/net?k8s-version=$kubever"')
        master_config['runcmd'].append(r'kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/master/src/deploy/alternative/kubernetes-dashboard-arm.yaml')
        master_config['runcmd'].append(r'mkdir -p /root/.kube')
        master_config['runcmd'].append(r'cp /etc/kubernetes/admin.conf /root/.kube/config')

    # Add the other config options
    master_config['locale'] = "en_US.UTF-8"
    master_config['manage_etc_hosts'] = True

    # Add the network config
    master_config['write_files'] = build_network_config(config, 200)

    # If batman is selected, then add it to the writefiles
    if config['network']['wlan']['mesh']['enabled']:
        master_config['write_files'].append(configure_alfred())
        master_config['write_files'].append(configure_batvis())
        master_config['write_files'].append(dhcp_default())
        master_config['write_files'].append(configure_dhcp())

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

    # Master Address
    if config['network']['wlan']['mesh']['enabled']:
        master_ip = "10.12.29.254"
    else:
        master_ip = "{0}-master".format(config['host-prefix'])

    # Join the cluster
    node_config['runcmd'].append(r'kubeadm join --token {0} {1}:6443 --discovery-token-unsafe-skip-ca-verification'.format(token, master_ip.strip()))

    # Add network config
    node_config['write_files'] = build_network_config(config, node)

    # If batman is selected, then add it to the writefiles
    if config['network']['wlan']['mesh']['enabled']:
        node_config['write_files'].append(configure_alfred())
        node_config['write_files'].append(configure_batvis())

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
    logging.basicConfig( format="%(asctime)s %(levelname)7s  %(funcName)20s %(message)s")
    LOG = logging.getLogger("pikube")
    LOG.setLevel(logging.DEBUG)
    PP = pprint.PrettyPrinter(depth=6)

    build_configs()
