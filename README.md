# Pikube Cluster Cloud Init Generator

This is a set of python functions and some other stuff to allow you to generate cloud init files for a pi kube cluster.  These can then be flashed using the hypriot flash utility to build a pi cluster

## Usage

* Create a cluster_config.yaml based on the example in the file.  You can create multiple users and set wifi/lan info here
* If you delete the token field, one will be randomly generated for you
* Make sure you have all the packages installed in requirements.txt
* Run `./gen_configs.py`
* Run `./flash.sh <cluster prefix>`, this will start a flash of the SD Cards (requires hypriot flash utility from references)
* Cluster should come up several minutes after booting the Pis.  This can take a while.

Note: The kubeconfig to access the cluster will be in /etc/kubernetes/admin.conf.  You will need this to use kubectl

## Other

You can use the flash.sh to flash a single node's card.  Just use `./flash.sh <prefix>-nodeX.yaml`

If you want to no overwrite once you have a token, just put the token in the cluster config.  This will overwrite, but with the same token so your kube cluster will continue to work.

## References

This is all utilizing a ton of work by hypriot.  Thanks!

https://blog.hypriot.com/post/cloud-init-cloud-on-hypriot-x64/
https://github.com/hypriot/flash

