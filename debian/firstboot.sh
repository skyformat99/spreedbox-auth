#!/bin/sh

# Make sure the key is regenerated on first boot
rm -f /etc/spreedbox/auth/keys/privkey.pem

dpkg-reconfigure spreedbox-authd