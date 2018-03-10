# Pikube Cluster Cloud Init Generator

This is a set of python functions and some other stuff to allow you to generate cloud init files for a pi kube cluster.  These can then be flashed using the hypriot flash utility to build a pi cluster

## Requirements

There's a few things that require this to work out of the box:

* The hypriot flash utility (see references)
* A router that will allow you to discover the other Pi nodes via DNS.  I use a travel router with openwrt.  This enables the pis to look each other up by name.  You could also do this with static entries.
* Some SD cards.  Preferably class 10 or better
* Some Pis.  I use 5.  It's up to you

## Usage

* Create a cluster_config.yaml based on the example in the file.  You can create multiple users and set wifi/lan info here
* If you delete the token field, one will be randomly generated for you
* Make sure you have all the packages installed in requirements.txt
* Run `./gen_configs.py`
* Run `./flash.sh <cluster prefix>`, this will start a flash of the SD Cards (requires hypriot flash utility from references)
* Start up the first node right away.  This one takes the longest.
* Then start the other nodes and they will join the cluster.  This can take a while.

Note: The kubeconfig to access the cluster will be in /etc/kubernetes/admin.conf.  You will need this to use kubectl

## Other Notes

### Networking

I use weavenet because it's the easiest to get working with kubeadm.  Right now this tool doesn't support anything else.

Also, I am using some specific address ranges inside the cidr that you specify.  I may add a way to change these, but until then deal with these:

* 1-x For the nodes
* 254 - gateway
* 200 - The master.  I figured you wouldn't have more than 199 nodes using this

### Self-Hosted

I really like the self hosted kubernetes model.  Enable that in the kubeadm section of cluster_config.yaml

### Helm

If you want to install a tiller for helm, use this

```
helm init --tiller-image timotto/rpi-tiller:latest --service-account tiller
```

### flash.sh

You can use the flash.sh to flash a single node's card.  Just use `./flash.sh <prefix>-nodeX.yaml`

If you want to no overwrite once you have a token, just put the token in the cluster config.  This will overwrite, but with the same token so your kube cluster will continue to work.

## Useful commands

Find the bat0 link-local address:

```
ip addr show bat0 | grep -Po 'inet \K[\d.]+'
```

Find the mesh IPs
```
avahi-browse --terminate --ignore-local --verbose -p  -a | grep bat | grep IPv4
```

Decode a file out of an existing config for debugging
```
decode_file.sh <prefix>-master.yaml <filename>

## References

This is all utilizing a ton of work by hypriot.  Thanks!

https://blog.hypriot.com/post/cloud-init-cloud-on-hypriot-x64/
https://github.com/hypriot/flash
