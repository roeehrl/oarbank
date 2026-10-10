#!/bin/sh
# After the package went. deb's purge (`apt purge oarbank-agent`, `dpkg --purge`) deletes the node for good: its home
# under /var/lib/oarbank (keys, certificate, caches, logs, container storage) and its status. A plain remove (and rpm's
# erase, $1 = 0, as rpm has no purge) keeps them: preremove.sh stopped the service, and reinstalling brings the same
# node back.
#
# What purge keeps, by Debian and Fedora convention: the `oarbank` system account (files a job left elsewhere may carry
# its id; a reused id would inherit them; `userdel oarbank` removes it), and an administrator's /etc/oarbank/policy.json
# (theirs, not the package's; dpkg removes /etc/oarbank once it is empty). The launcher is gone by now, so this is
# plain shell. The coordinator lists the node until its owner removes it in the console.
set -u
case "${1:-}" in
    purge)
        rm -rf /var/lib/oarbank
        echo "Oarbank: purged this node's identity and data (/var/lib/oarbank); the oarbank account stays (userdel oarbank)"
        ;;
esac
exit 0
