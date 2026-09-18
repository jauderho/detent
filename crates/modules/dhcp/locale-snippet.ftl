## dhcp module — display name, security notes, schema tooltips
dhcp-name = dhcp
dhcp-note-commit-confirm = a bad DHCP change cuts every client, and you, off the network; check the diff carefully before confirming.
dhcp-tip-dnsmasq = the `key=value` settings of /etc/dnsmasq.conf, in file order; comments and unknown lines are preserved untouched.
dhcp-tip-kea-v4 = the managed subset of the Kea DHCPv4 server (`Dhcp4`); unknown Kea options are preserved untouched.
dhcp-tip-kea-v6 = the managed subset of the Kea DHCPv6 server (`Dhcp6`); unknown Kea options are preserved untouched.
dhcp-tip-key = the dnsmasq option name, one word, no whitespace.
dhcp-tip-value = the value after `=`; a bare flag such as `domain-needed` has no value.
dhcp-tip-interfaces = the interfaces the Kea server listens on; an empty list means the server answers on every interface.
dhcp-tip-valid-lifetime = the default lease lifetime in seconds; 3600 is a sane default for most networks.
dhcp-tip-subnets = the subnets the server assigns addresses from.
dhcp-tip-id = Kea's stable subnet identifier; keep it stable across edits, leases are keyed by it.
dhcp-tip-subnet = the subnet prefix in CIDR form, e.g. `192.168.1.0/24`.
dhcp-tip-pools = the dynamic address pools of the subnet.
dhcp-tip-routers = the routers (default gateway) option handed to clients.
dhcp-tip-domain-servers = the DNS servers (`domain-name-servers`) handed to clients.
dhcp-tip-pool = a pool as a range `192.168.1.100 - 192.168.1.200` or a prefix `192.168.1.0/24`.

## dhcp module — validation diagnostics
dhcp-empty-key = a dnsmasq setting has an empty option name.
dhcp-invalid-key = `{$key}` is not a valid dnsmasq option name; it must be one word without whitespace, `=` or `#`.
dhcp-malformed-cidr = `{$value}` is not a valid CIDR prefix, e.g. `192.168.1.0/24`.
dhcp-malformed-pool = `{$value}` is not a valid pool; use a range like `192.168.1.100 - 192.168.1.200` or a CIDR prefix.
dhcp-authoritative-set = `dhcp-authoritative` makes dnsmasq the sole DHCP server on the segment; only set it when no other DHCP server exists.
dhcp-kea-interfaces-empty = {$server} has no interfaces configured and will listen on every interface; name the interfaces explicitly.
dhcp-rec-rebind = domain-needed and bogus-priv are not both set; they filter rebind attacks and upstream A-for-private queries.
dhcp-rec-lifetime = {$server} has valid-lifetime {$lifetime}; keep it between 300 and 86400 seconds so leases renew predictably.
