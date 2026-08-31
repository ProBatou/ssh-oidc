#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "Run this installer as root." >&2
  exit 1
fi

for cmd in make cc; do
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "$cmd is required to build the native PAM module." >&2
    exit 1
  }
done

make install

echo
echo "Installed pam_ssh_oidc.so and the example configuration when absent."
echo "Edit /etc/security/pam-ssh-oidc.conf before enabling PAM."
echo "PAM and sshd are intentionally NOT modified automatically."
echo "Keep an existing console/session open and validate sshd configuration before restarting SSH."
