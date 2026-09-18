## network module — display name, security notes, schema tooltips
network-name = network
network-note-precedence = a bad network configuration can cut the admin off from this host; every change needs a second confirmation.
network-tip-interfaces = the interfaces this host configures, in file order.
network-tip-iface-name = the interface name, e.g. eth0.
network-tip-iface-dhcp-v4 = whether this interface gets its IPv4 address via DHCP.
network-tip-iface-dhcp-v6 = whether this interface gets its IPv6 address via DHCP.
network-tip-iface-addresses = static addresses in CIDR notation, e.g. 192.168.1.10/24.
network-tip-iface-gateway-v4 = the default gateway for IPv4, when statically addressed.
network-tip-iface-gateway-v6 = the default gateway for IPv6, when statically addressed.
network-tip-iface-dns = DNS servers for this interface.
network-tip-iface-routes = static routes for this interface.
network-tip-iface-vlan = VLAN settings for this interface, when it is a VLAN.
network-tip-iface-bridge = bridge settings for this interface, when it is a bridge.
network-tip-route-to = the destination CIDR or default.
network-tip-route-via = the next-hop IP.
network-tip-vlan-link = the parent link for this VLAN, e.g. eth0.
network-tip-vlan-id = the VLAN id, 1–4094.
network-tip-bridge-members = member interface names for this bridge.

## network module — validation diagnostics
network-invalid-cidr = `{$value}` is not a valid CIDR address.
network-invalid-ip = `{$value}` is not a valid IP address.
network-gateway-outside-subnet = gateway `{$gateway}` is outside this interface's subnets.
network-vlan-range = VLAN id `{$id}` is outside 1–4094.
network-duplicate-interface = interface `{$name}` appears more than once.
network-injection = `{$value}` contains a line break or null byte.
network-static-no-gateway = this statically addressed interface has no gateway.
network-static-no-dns = this statically addressed interface has no DNS servers.
network-dhcp-static-mixed = this interface has both DHCP and static addresses.
network-rec-ipv6-privacy = enable IPv6 privacy extensions when DHCPv6 is on.
network-rec-ra-accept = accept router advertisements only when DHCPv6 is explicitly managed.
network-rec-no-promisc = this interface should not run in promiscuous mode.
