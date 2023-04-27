#!/bin/sh
for i in /sys/bus/pci/drivers/[uoex]hci_hcd/*:*; do
  [ -e "$i" ] || continue
  echo "${i##*/}" > "${i%/*}/unbind"
  echo "${i##*/}" > "${i%/*}/bind"
done

find /sys/bus/usb/devices/*/authorized -exec sh -c 'echo 0 > ${0}; echo 1 > ${0}' {} \;