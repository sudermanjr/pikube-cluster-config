for i in $(ls *-node.yaml); do
    echo "Flashing $i. Please insert the SD card for it..."
    flash \
        --bootconf no-uart-config.txt \
        --userdata $i \
        https://github.com/hypriot/image-builder-rpi/releases/download/v1.7.1/hypriotos-rpi-v1.7.1.img.zip
done
