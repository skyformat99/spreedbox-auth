#!/bin/sh

# Make sure the key is regenerated on first boot
rm -f /etc/spreedbox/auth/keys/privkey.pem
/usr/share/spreedbox-authd/spreedbox-authd-genkey-helper firstboot
