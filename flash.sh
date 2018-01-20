#!/bin/bash

# Need a prefix name
if [ -z "$1" ]
  then
    echo "No argument supplied, please specify your cluster prefix"
    exit 1
fi

echo "This will flash all the configs for the $1 cluster"

for i in $(ls $1*.yaml); do
    echo "Flashing $i. Please insert the SD card for it..."
    flash \
        --bootconf no-uart-config.txt \
        --userdata $i \
        https://github.com/hypriot/image-builder-rpi/releases/download/v1.7.1/hypriotos-rpi-v1.7.1.img.zip
done
