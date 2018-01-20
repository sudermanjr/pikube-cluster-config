# Pikube Cluster Cloud Init Generator

This is a set of python functions and some other stuff to allow you to generate cloud init files for a pi kube cluster.  These can then be flashed using the hypriot flash utility to build a pi cluster

## Usage

* Create a cluster_config.yaml based on the example in the file.  You can create multiple users and set wifi/lan info here
* If you delete the token field, one will be randomly generated for you
* Make sure you have all the packages installed in requirements.txt
* Run `./gen_configs.py`
* Now run the flash utility to flash these cloud configs to your SD cards (requires hypriot flash, see references)
* Cluster should come up several minutes after booting the Pis.  This can take a while.

Note: The kubeconfig to access the cluster will be in /etc/kubernetes/admin.conf.  You will need this to use kubectl

## References

This is all utilizing a ton of work by hypriot.  Thanks!

https://blog.hypriot.com/post/cloud-init-cloud-on-hypriot-x64/
https://github.com/hypriot/flash

