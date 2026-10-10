# needs-review: machine-drafted Bengali translation; not yet checked by a native speaker.
## detent-core — bn
## Source: locales/en-US/core.ftl. Same ids, same placeables. Code-like tokens
## (directive names, paths, flags, option values) stay untranslated.

## chrony module — display name, security notes, schema tooltips
chrony-name = chrony
chrony-note-precedence = এই ফাইলটি কম্পাইল করা ডিফল্ট মানগুলোকে ওভাররাইড করে; ভুল মান নীরবে বদলে দেয় হোস্ট কীভাবে সময় রাখে।
chrony-tip-settings = chrony.conf-এর যে ডিরেক্টিভগুলো এই মডিউল মডেল করে, ফাইলের ক্রমে; ফাইলের বাকি সবকিছু অক্ষত থাকে।
chrony-tip-key = ডিরেক্টিভের নাম, এক শব্দ, বড়/ছোট হাতের অক্ষর নির্বিশেষে।
chrony-tip-value = এই ডিরেক্টিভের মান, লাইনের শেষ পর্যন্ত; `rtcsync`-এর মতো মানহীন ডিরেক্টিভের জন্য ফাঁকা।
chrony-rec-value = কম্পাইল করা ডিফল্টের ওপর নির্ভর না করে স্পষ্ট মান দিন।

## chrony module — validation diagnostics
chrony-privileged-directive = `{$key}` এমন একটি ফাইল সেট করে যা chronyd root হিসেবে লেখে, অথবা যে ব্যবহারকারী হিসেবে সে চলে। প্রয়োগ করার আগে মানটি যাচাই করুন।
chrony-invalid-key = `{$key}` একটি বৈধ chrony ডিরেক্টিভের নাম নয়।
chrony-duplicate-key = `{$key}` একাধিকবার সেট করা হয়েছে; শেষ মানটি কার্যকর হয়।
chrony-too-many-settings = এই ফাইলে {$count}টি সেটিং আছে; এটিকে /etc/chrony/conf.d-এর অধীনে ড্রপ-ইন ফাইলে ভাগ করুন।
chrony-allow-open = `allow {$value}` পুরো ইন্টারনেটকে সময় সরবরাহ করে; শুধু যে নেটওয়ার্কগুলোর প্রয়োজন তাদেরই অনুমতি দিন।
chrony-missing-makestep = makestep সেট করা নেই; স্টার্টআপে ঘড়িকে সীমার মধ্যে আনার বদলে সেটি সীমাহীনভাবে সরে যেতে পারে।
chrony-missing-rtcsync = rtcsync সেট করা নেই; হার্ডওয়্যার ঘড়ি সিস্টেম ঘড়ির তুলনায় সরে যেতে থাকবে।
chrony-rec-nts = পুল {$pool} nts অপশন ছাড়া ব্যবহার করা হচ্ছে; nts-সক্ষম উৎস বেছে নিন যাতে সময় স্পুফ করা না যায়।
chrony-cmdport-open = cmdport হলো {$port}; chronyc-কে নেটওয়ার্কের মাধ্যমে এই হোস্টে পৌঁছাতে না হলে cmdport 0 সেট করুন।
chrony-external-directive = `{$key}` বাইরের ফাইল লোড করে বা বাইরের প্রোগ্রাম চালায়; যে ডিরেক্টিভ এই মডিউলের নির্ধারিত ফাইল-সীমা অতিক্রম করে, মডিউলটি সেগুলো প্রত্যাখ্যান করে।

## dhcp module — display name, security notes, schema tooltips
dhcp-name = dhcp
dhcp-note-commit-confirm = DHCP-তে ভুল পরিবর্তন প্রতিটি ক্লায়েন্টকে এবং আপনাকেও নেটওয়ার্ক থেকে বিচ্ছিন্ন করে দেয়; নিশ্চিত করার আগে diff সতর্কভাবে দেখুন।
dhcp-tip-dnsmasq = /etc/dnsmasq.conf-এর `key=value` সেটিংগুলো, ফাইলের ক্রমে; মন্তব্য ও অজানা লাইন অক্ষত থাকে।
dhcp-tip-kea-v4 = Kea DHCPv4 সার্ভারের (`Dhcp4`) পরিচালিত অংশ; অজানা Kea অপশন অক্ষত থাকে।
dhcp-tip-kea-v6 = Kea DHCPv6 সার্ভারের (`Dhcp6`) পরিচালিত অংশ; অজানা Kea অপশন অক্ষত থাকে।
dhcp-tip-key = dnsmasq অপশনের নাম, এক শব্দ, কোনো ফাঁকা স্থান ছাড়া।
dhcp-tip-value = `=`-এর পরের মান; `domain-needed`-এর মতো একক ফ্ল্যাগের কোনো মান থাকে না।
dhcp-tip-interfaces = যে ইন্টারফেসগুলোতে Kea সার্ভার শোনে; খালি তালিকার অর্থ সার্ভার প্রতিটি ইন্টারফেসে সাড়া দেয়।
dhcp-tip-valid-lifetime = সেকেন্ডে ডিফল্ট লিজ মেয়াদ; বেশির ভাগ নেটওয়ার্কের জন্য 3600 যুক্তিসংগত ডিফল্ট।
dhcp-tip-subnets = যে সাবনেট থেকে সার্ভার ঠিকানা বরাদ্দ করে।
dhcp-tip-id = Kea-এর স্থিতিশীল সাবনেট শনাক্তকারী; সম্পাদনার সময় এটি অপরিবর্তিত রাখুন, লিজগুলো এর সঙ্গে যুক্ত।
dhcp-tip-subnet = CIDR আকারে সাবনেট প্রিফিক্স, যেমন `192.168.1.0/24`।
dhcp-tip-pools = সাবনেটের ডাইনামিক ঠিকানা পুল।
dhcp-tip-routers = ক্লায়েন্টকে দেওয়া রাউটার (ডিফল্ট গেটওয়ে) অপশন।
dhcp-tip-domain-servers = ক্লায়েন্টকে দেওয়া DNS সার্ভার (`domain-name-servers`)।
dhcp-tip-pool = রেঞ্জ `192.168.1.100 - 192.168.1.200` বা প্রিফিক্স `192.168.1.0/24` আকারে একটি পুল।

## dhcp module — validation diagnostics
dhcp-empty-key = একটি dnsmasq সেটিংয়ের অপশনের নাম খালি।
dhcp-invalid-key = `{$key}` একটি বৈধ dnsmasq অপশনের নাম নয়; এটি ফাঁকা স্থান, `=` বা `#` ছাড়া এক শব্দ হতে হবে।
dhcp-malformed-cidr = `{$value}` একটি বৈধ CIDR প্রিফিক্স নয়, যেমন `192.168.1.0/24`।
dhcp-malformed-pool = `{$value}` একটি বৈধ পুল নয়; `192.168.1.100 - 192.168.1.200`-এর মতো রেঞ্জ বা CIDR প্রিফিক্স ব্যবহার করুন।
dhcp-external-directive = `{$key}` বাইরের ফাইল লোড করে বা কমান্ড চালায়; যে ডিরেক্টিভ এই মডিউলের নির্ধারিত ফাইল-সীমা অতিক্রম করে, মডিউলটি সেগুলো তৈরি বা পরিবর্তন করবে না।
dhcp-authoritative-set = `dhcp-authoritative` dnsmasq-কে ওই সেগমেন্টের একমাত্র DHCP সার্ভার বানায়; অন্য কোনো DHCP সার্ভার না থাকলেই কেবল এটি সেট করুন।
dhcp-kea-interfaces-empty = {$server}-এ কোনো ইন্টারফেস কনফিগার করা নেই এবং এটি প্রতিটি ইন্টারফেসে শুনবে; ইন্টারফেসের নাম স্পষ্টভাবে দিন।
dhcp-rec-rebind = domain-needed ও bogus-priv দুটোই সেট করা নেই; এগুলো রিবাইন্ড আক্রমণ এবং ব্যক্তিগত ঠিকানার জন্য আপস্ট্রিমে পাঠানো A কোয়েরি ছেঁকে ফেলে।
dhcp-rec-lifetime = {$server}-এর valid-lifetime হলো {$lifetime}; লিজ যাতে অনুমানযোগ্যভাবে নবায়ন হয় সেজন্য এটি ৩০০ থেকে ৮৬৪০০ সেকেন্ডের মধ্যে রাখুন।

## hosts module — display name, security notes, schema tooltips
hosts-name = hosts
hosts-note-spoofing = এখানকার এন্ট্রি DNS-কে ওভাররাইড করে; ভুল বা ক্ষতিকর এন্ট্রি নীরবে লুকআপ অন্যত্র সরিয়ে দেয়।
hosts-tip-entries = /etc/hosts-এ ঠিকানা-থেকে-নামের ম্যাপিং, ফাইলের ক্রমে।
hosts-tip-ip = নিচের নামগুলো যে ঠিকানায় রিজলভ হয়।
hosts-tip-hostnames = যে নামগুলো এই ঠিকানায় রিজলভ হয়, ক্যানোনিকাল নাম প্রথমে।
hosts-tip-comment = এই এন্ট্রির ইনলাইন মন্তব্য, থাকলে।

## hosts module — validation diagnostics
hosts-invalid-hostname = `{$name}` একটি বৈধ হোস্টনেম নয়।
hosts-duplicate-canonical = `{$name}` একাধিক এন্ট্রির ক্যানোনিকাল নাম।
hosts-no-hostnames = এই এন্ট্রিতে কোনো হোস্টনেম নেই।
hosts-hostname-is-ip = `{$name}` একটি ঠিকানা, হোস্টনেম নয়।
hosts-ipv6-zone-unsupported = `{$name}`-এ ipv6 জোন আইডি আছে, যা /etc/hosts সমর্থন করে না।
hosts-hostname-multiple-ips = `{$name}` একই পরিবারের একাধিক ঠিকানায় রিজলভ হয়।
hosts-localhost-not-loopback = `localhost` `{$ip}`-এর দিকে নির্দেশ করে, যা লুপব্যাক ঠিকানা নয়।
hosts-missing-localhost = কোনো `localhost` এন্ট্রি নেই।
hosts-missing-ipv6-localhost = কোনো ipv6 `localhost` এন্ট্রি নেই।
hosts-too-many-entries = এই ফাইলে {$count}টি এন্ট্রি আছে; এর বদলে DNS বিবেচনা করুন।

## mounts module — display name, security notes, schema tooltips
mounts-name = mounts
mounts-note-boot = ভুল /etc/fstab পরবর্তী রিস্টার্টে হোস্টকে বুট-অক্ষম করে দিতে পারে; প্রতিটি পরিবর্তনে দ্বিতীয়বার নিশ্চিত করতে হয়। নিশ্চিতকরণ ভুল এন্ট্রি ধরতে পারে না, কারণ পরবর্তী বুটের আগে কেউ ফাইলটি পড়ে না।
mounts-tip-entries = /etc/fstab-এর মাউন্ট এন্ট্রি, ফাইলের ক্রমে।
mounts-tip-spec = কী মাউন্ট হচ্ছে: একটি ডিভাইস, `UUID=...`/`LABEL=...`, একটি nfs এক্সপোর্ট, অথবা সোয়াপের জন্য `none`।
mounts-tip-mountpoint = ফাইল সিস্টেম কোথায় মাউন্ট হয়, অথবা সোয়াপের জন্য `none`/`swap`।
mounts-tip-fstype = ফাইল সিস্টেমের ধরন, যেমন ext4, বা `swap`।
mounts-tip-options = কমা দিয়ে আলাদা করা মাউন্ট অপশন, যেমন defaults,nosuid।
mounts-tip-dump = dump(8) ব্যাকআপের ফ্রিকোয়েন্সি; প্রায় সবসময় 0।
mounts-tip-pass = fsck পাস নম্বর: root-এর জন্য 1, যাচাই করা অন্য ফাইল সিস্টেমের জন্য 2, বাদ দিতে 0।
mounts-rec-options = ব্যবহারকারী-লেখার-যোগ্য ডেটা nosuid, nodev ও noexec দিয়ে সুরক্ষিত করুন; নেটওয়ার্ক ফাইল সিস্টেমে x-systemd.automount পছন্দ করুন।

## mounts module — validation diagnostics
mounts-empty-spec = এন্ট্রি {$index}-এর spec (প্রথম কলাম) খালি।
mounts-empty-mountpoint = এন্ট্রি {$index}-এর মাউন্ট পয়েন্ট (দ্বিতীয় কলাম) খালি।
mounts-invalid-fstype = `{$fstype}` একটি বৈধ ফাইল সিস্টেমের ধরন নয়।
mounts-pass-too-high = এন্ট্রি {$index}-এর pass `{$pass}`; fsck সর্বোচ্চ ২টি পাস চালায়।
mounts-root-pass = root ফাইল সিস্টেমের pass 1 হওয়া উচিত, `{$pass}` নয়।
mounts-missing-nofail = `{$mountpoint}` `nofail` ছাড়া রিমুভেবল মিডিয়া; খুলে নিলে বুট আটকে যায়।
mounts-missing-boot-escape = `{$mountpoint}`-এ nofail বা noauto কোনোটিই নেই; মাউন্ট ব্যর্থ হলে বুট আটকে যেতে পারে।
mounts-critical-noauto = `{$mountpoint}` বুটের জন্য আবশ্যক কিন্তু এতে noauto আছে, তাই সিস্টেম এটি ছাড়াই এগিয়ে যেতে পারে।
mounts-missing-guards = `{$mountpoint}` ব্যবহারকারী-লেখার-যোগ্য ডেটা `{$missing}` ছাড়া মাউন্ট করে; এগুলো যোগ করুন।
mounts-network-automount = `{$mountpoint}` `x-systemd.automount` ছাড়া একটি নেটওয়ার্ক ফাইল সিস্টেম; বুট নেটওয়ার্কের জন্য অপেক্ষা করে।
mounts-noauto-without-user = `user` ছাড়া `noauto`: কেবল root এটি মাউন্ট করতে পারে, ফলে উদ্দেশ্যই ব্যর্থ হয়।
mounts-relative-mountpoint = এন্ট্রি {$index} `{$mountpoint}`-এ মাউন্ট করে, যা একটি পরম পাথ নয়।
mounts-no-root-entry = কোনো এন্ট্রি `/` মাউন্ট করে না; root ফাইল সিস্টেম অন্য কোনোভাবে মাউন্ট হয় কি না যাচাই করুন।

## network module — display name, security notes, schema tooltips
network-name = network
network-note-precedence = ভুল নেটওয়ার্ক কনফিগারেশন অ্যাডমিনকে এই হোস্ট থেকে বিচ্ছিন্ন করে দিতে পারে; প্রতিটি পরিবর্তনে দ্বিতীয়বার নিশ্চিত করতে হয়।
network-tip-interfaces = এই হোস্ট যে ইন্টারফেসগুলো কনফিগার করে, ফাইলের ক্রমে।
network-tip-iface-name = ইন্টারফেসের নাম, যেমন eth0।
network-tip-iface-dhcp-v4 = এই ইন্টারফেস DHCP-র মাধ্যমে তার IPv4 ঠিকানা পায় কি না।
network-tip-iface-dhcp-v6 = এই ইন্টারফেস DHCP-র মাধ্যমে তার IPv6 ঠিকানা পায় কি না।
network-tip-iface-addresses = CIDR নোটেশনে স্ট্যাটিক ঠিকানা, যেমন 192.168.1.10/24।
network-tip-iface-gateway-v4 = IPv4-এর ডিফল্ট গেটওয়ে, ঠিকানা স্ট্যাটিক হলে।
network-tip-iface-gateway-v6 = IPv6-এর ডিফল্ট গেটওয়ে, ঠিকানা স্ট্যাটিক হলে।
network-tip-iface-dns = এই ইন্টারফেসের জন্য DNS সার্ভার।
network-tip-iface-routes = এই ইন্টারফেসের জন্য স্ট্যাটিক রুট।
network-tip-iface-vlan = এই ইন্টারফেসের VLAN সেটিং, এটি VLAN হলে।
network-tip-iface-bridge = এই ইন্টারফেসের ব্রিজ সেটিং, এটি ব্রিজ হলে।
network-tip-route-to = গন্তব্য CIDR বা default।
network-tip-route-via = নেক্সট-হপ IP।
network-tip-vlan-link = এই VLAN-এর প্যারেন্ট লিংক, যেমন eth0।
network-tip-vlan-id = VLAN আইডি, 1–4094।
network-tip-bridge-members = এই ব্রিজের সদস্য ইন্টারফেসের নাম।

## network module — validation diagnostics
network-invalid-cidr = `{$value}` একটি বৈধ CIDR ঠিকানা নয়।
network-invalid-ip = `{$value}` একটি বৈধ IP ঠিকানা নয়।
network-gateway-outside-subnet = গেটওয়ে `{$gateway}` এই ইন্টারফেসের সাবনেটের বাইরে।
network-vlan-range = VLAN আইডি `{$id}` 1–4094-এর বাইরে।
network-duplicate-interface = ইন্টারফেস `{$name}` একাধিকবার এসেছে।
network-interface-order = ইন্টারফেস `{$name}` তার ওপরের ইন্টারফেসগুলোর আগে আসতে হবে: ইন্টারফেস নামের ক্রমে তালিকাভুক্ত করুন।
network-injection = `{$value}`-এ নতুন লাইন বা null বাইট আছে।
network-static-no-gateway = স্ট্যাটিক ঠিকানার এই ইন্টারফেসে কোনো গেটওয়ে নেই।
network-static-no-dns = স্ট্যাটিক ঠিকানার এই ইন্টারফেসে কোনো DNS সার্ভার নেই।
network-dhcp-static-mixed = এই ইন্টারফেসে DHCP ও স্ট্যাটিক ঠিকানা দুটোই আছে।
network-rec-ipv6-privacy = DHCPv6 চালু থাকলে IPv6 প্রাইভেসি এক্সটেনশন চালু করুন।
network-rec-ra-accept = DHCPv6 স্পষ্টভাবে পরিচালিত হলেই কেবল রাউটার অ্যাডভার্টাইজমেন্ট গ্রহণ করুন।
network-rec-no-promisc = এই ইন্টারফেস প্রমিসকিউয়াস মোডে চালানো উচিত নয়।

## nfs module — display name, security notes, schema tooltips
nfs-name = nfs
nfs-note-live-state = এক্সপোর্ট কার্নেল প্রতিটি মাউন্টে প্রয়োগ করে; ভুল লাইন নীরবে বদলে দেয় কোন হোস্ট কোন ফাইল সিস্টেম পড়তে পারবে।
nfs-tip-entries = /etc/exports-এর এক্সপোর্ট, ফাইলের ক্রমে।
nfs-tip-path = এক্সপোর্ট পয়েন্ট: এই হোস্টে একটি পরম ডিরেক্টরি পাথ।
nfs-tip-clients = যে হোস্টগুলোকে এই এক্সপোর্ট মাউন্ট করার অনুমতি আছে, মিলানোর ক্রমে; প্রথম মিলে যাওয়া নির্দিষ্টকরণ কার্যকর হয়।
nfs-tip-host = ক্লায়েন্ট নির্দিষ্টকরণ: একটি নাম, ঠিকানা, ঠিকানা/নেটমাস্ক, ওয়াইল্ডকার্ড, `*` (প্রতিটি ক্লায়েন্ট), বা @netgroup।
nfs-tip-options = এই ক্লায়েন্টের এক্সপোর্ট অপশন, কমা দিয়ে আলাদা; খালি তালিকা ফাইলের ডিফল্ট নেয়।
nfs-rec-options = rw/ro, sync/async, root_squash ও subtree-র আচরণ স্পষ্টভাবে লিখুন; nfs-utils-এর রিলিজ ভেদে ডিফল্ট বদলায়।

## nfs module — validation diagnostics
nfs-empty-path = একটি এক্সপোর্ট পয়েন্ট খালি।
nfs-relative-path = `{$path}` পরম নয়; এক্সপোর্ট পয়েন্ট `/` দিয়ে শুরু হতে হবে।
nfs-empty-host = `{$path}`-এর একটি ক্লায়েন্টের কোনো হোস্ট নির্দিষ্টকরণ নেই।
nfs-bad-host = `{$host}` একটি বৈধ ক্লায়েন্ট নির্দিষ্টকরণ নয়; এটি `-` দিয়ে শুরু হয় বা এমন সিনট্যাক্স ধারণ করে যা লাইন কেটে দেবে।
nfs-bad-path = `{$path}`-এ এমন সিনট্যাক্স আছে যা এক্সপোর্ট লাইন কেটে দেবে।
nfs-bad-continuation = `{$path}` ধারাবাহিকতার ব্যাকস্ল্যাশ দিয়ে শেষ হবে এবং পরের লাইন জুড়ে নেবে।
nfs-invalid-option = `{$option}` একটি বৈধ এক্সপোর্ট অপশন নয়; অপশন হলো ফাঁকা স্থান বা বন্ধনী ছাড়া সাধারণ টোকেন।
nfs-no-root-squash = `{$host}` no_root_squash সহ মাউন্ট করে এবং এক্সপোর্টে root সুবিধা ধরে রাখে।
nfs-sec-sys-only = `{$host}` ডিফল্ট sec=sys ব্যবহার করে বা শুধু sec=sys নিয়ে সমঝোতা করে; ক্রিপ্টোগ্রাফিক সুরক্ষার জন্য krb5p যোগ করুন।
nfs-world-export = `{$host}` প্রতিটি ক্লায়েন্টের জন্য পড়া-লেখার উদ্দেশ্যে পৌঁছানো যায়।
nfs-subtree-undecided = `{$host}`-এ subtree_check বা no_subtree_check কোনোটিই নেই; আপস্ট্রিম ডিফল্ট বদলেছে, তাই কোনটি চান তা বলুন।
nfs-root-squash-undecided = `{$host}`-এ root_squash বা no_root_squash কোনোটিই নেই; কোনটি চান তা বলুন।
nfs-sync-undecided = `{$host}`-এ sync বা async কোনোটিই নেই; sync পছন্দ করুন, যা লেখা স্থিতিশীল স্টোরেজে কমিট করে।

## resolver module — display name, security notes, schema tooltips
resolver-name = resolver
resolver-note-managed-symlink = এই হোস্টে /etc/resolv.conf একটি রিজলভার ব্যাকএন্ড পরিচালনা করে; detent পরিচালিত সিমলিংকের লক্ষ্য সম্পাদনা করতে অস্বীকার করে এবং এর বদলে ব্যাকএন্ড কনফিগার করে।
resolver-tip-resolv = /etc/resolv.conf-এর যে ডিরেক্টিভগুলো এই মডিউল মডেল করে; ফাইলের বাকি সবকিছু অক্ষত থাকে।
resolver-tip-resolved = systemd-resolved-এর সেটিং, ফাইলের ক্রমে। এগুলো বদলালে systemd-resolved রিস্টার্ট হয়।
resolver-tip-unbound = unbound.conf-এর যে আইটেমগুলো এই মডিউল মডেল করে, ফাইলের ক্রমে। এগুলো বদলালে unbound রিস্টার্ট হয়।

## resolver module — validation diagnostics
resolver-no-nameserver = কোনো nameserver কনফিগার করা নেই।
resolver-duplicate-nameserver = `{$ip}` একাধিক nameserver হিসেবে এসেছে।
resolver-too-many-nameservers = এই ফাইলে {$count}টি nameserver তালিকাভুক্ত; glibc সর্বোচ্চ {$max}টি পড়ে।
resolver-invalid-domain = `{$domain}` একটি বৈধ ডোমেইন নাম নয়।
resolver-unknown-option = `{$option}` এমন অপশন নয় যা glibc-র resolv.conf পার্সার গ্রহণ করে।
resolver-search-and-domain = `search` ও `domain` দুটোই আছে; `search` সেট থাকলে glibc `domain` উপেক্ষা করে।
resolver-no-config = এই মডেল কোনো রিজলভার ব্যাকএন্ডই কনফিগার করে না।
resolver-backend-missing = এই সেটিংগুলো {$service} কনফিগার করে, যা এই হোস্টে পাওয়া যায়নি।
resolver-rec-dnssec = DNSSEC allow-downgrade-এ সেট করা; `DNSSEC=yes` কঠোরভাবে যাচাই করে এবং আপস্ট্রিম ডেটা অনুমতি দিলে এটি সুপারিশ করা হয়।
resolver-rec-dot = DNSOverTLS সুযোগসন্ধানী, যা সাধারণ টেক্সটে ডাউনগ্রেড হয়; `DNSOverTLS=yes` এর বদলে TLS বাধ্যতামূলক করে।
resolver-unknown-hardening = `{$key}` এমন ডিরেক্টিভ নয় যা এই মডিউল unbound-এর জন্য মডেল করে।
resolver-unbound-misplaced = `{$key}` unbound.conf-এর {$section} সেকশনের, এখানকার নয়।
resolver-invalid-forward-addr = `{$addr}` ip[@port][#auth-name] আকারের বৈধ forward-addr নয়।
resolver-invalid-forward-name = `{$name}` একটি বৈধ forward-zone নাম নয়।
resolver-forward-tls-no-auth = এই জোন তার forward-addr-এ `#auth-name` ছাড়া TLS-এর মাধ্যমে ফরওয়ার্ড করে, তাই TLS সংযোগ প্রমাণীকৃত নয়।
resolver-rec-hardening = `{$key}` বন্ধ আছে; এটি চালু করলে unbound আপস্ট্রিম স্পুফিং ও ডেলিগেশনের অপব্যবহারের বিরুদ্ধে আরও সুরক্ষিত হয়।
resolver-forward-zone-unnamed = name: ছাড়া একটি forward-zone: কিছুই ফরওয়ার্ড করে না এবং কনফিগারেশনকে দুর্বল করে; প্রতিটি জোনকে একটি নাম দিন।

## samba module — display name, security notes, schema tooltips
samba-name = samba
samba-note-guest-access = সংযোগের সময় প্রতিটি শেয়ারে গেস্ট অ্যাক্সেস দেওয়া হয়; ভুল মান পাসওয়ার্ড ছাড়াই ফাইল উন্মুক্ত করে দেয়।
samba-tip-entries = smb.conf-এর যে এন্ট্রিগুলো এই মডিউল মডেল করে, ফাইলের ক্রমে: `[section]` হেডার ও ডিরেক্টিভ উভয়ই।
samba-tip-section = `[section]` হেডারের জন্য সেকশনের নাম; সাধারণ ডিরেক্টিভ লাইনের জন্য ফাঁকা।
samba-tip-key = প্যারামিটারের নাম, বড়/ছোট হাতের অক্ষর নির্বিশেষে এবং সম্ভবত একাধিক শব্দের (`guest ok`)।
samba-tip-value = প্যারামিটারের মান, লাইনের শেষ পর্যন্ত; `%` ম্যাক্রো হুবহু সংরক্ষিত থাকে।
samba-rec-value = আপস্ট্রিমের কম্পাইল করা ডিফল্টের ওপর নির্ভর না করে স্পষ্ট কঠোর মান দিন।

## samba module — validation diagnostics
samba-empty-key = একটি ডিরেক্টিভের কোনো প্যারামিটারের নাম নেই।
samba-empty-section = একটি সেকশন হেডার খালি।
samba-bad-key = `{$key}` সেকশন বা মন্তব্য হিসেবে পার্স হবে, ডিরেক্টিভ কী হিসেবে নয়।
samba-bad-value = `{$value}` `\` দিয়ে শেষ হয় এবং পরের লাইন গিলে ফেলবে।
samba-bad-section = `{$section}`-এ `[` বা `]` আছে অথবা এটি `\` দিয়ে শেষ হয়, এবং এটি রাউন্ড-ট্রিপ করবে না।
samba-guest-ok = `guest ok` {$value} সেট করা; যে শেয়ার এটি উত্তরাধিকারসূত্রে পায় তার প্রতিটিতে অপ্রমাণীকৃত ক্লায়েন্ট সংযুক্ত হতে পারে।
samba-map-to-guest = `map to guest` হলো {$value}; Never ছাড়া অন্য যেকোনো মান ব্যর্থ লগইনকে গেস্ট সেশনে পরিণত করে।
samba-min-protocol = `server min protocol` হলো {$value}; অন্তত SMB3_00 সেট করুন এবং SMB1 যুগের প্রোটোকল স্তরগুলো বাদ দিন।
samba-smb-encrypt = `smb encrypt` হলো {$value}; required সেট করুন যাতে SMB ট্রাফিক এনক্রিপ্ট না করে যেতে না পারে।
samba-restrict-anonymous = `restrict anonymous` হলো {$value}; 2 অজ্ঞাতনামা ব্যবহারকারীদের কাছ থেকে শেয়ারের তালিকা লুকায়।
samba-rec-server-signing = `server signing` হলো {$value}; mandatory সেট করুন যাতে SMB ট্রাফিকে ক্রিপ্টোগ্রাফিক স্বাক্ষর থাকে।
samba-rec-load-printers = `load printers` হলো {$value}; এই হোস্ট সত্যিই প্রিন্টার শেয়ার না করলে no সেট করুন।
samba-rec-interfaces = কোনো `interfaces` ডিরেক্টিভ সেট করা নেই; samba-কে প্রতিটি ইন্টারফেসে শুনতে দেওয়ার বদলে স্পষ্ট ঠিকানায় বাঁধুন।
samba-writable-exposure = এই শেয়ার writeable, read only বা write list-এর মাধ্যমে লেখার অনুমতি দেয়; প্রতিটি ক্লায়েন্টের লেখার অ্যাক্সেস থাকা উচিত কি না নিশ্চিত করুন।
samba-root-command = `{$key}` প্রতিটি মিলে যাওয়া সংযোগে root সুবিধা নিয়ে একটি কমান্ড চালায়।
samba-client-command = `{$key}` ক্লায়েন্টকে samba দিয়ে কমান্ড চালাতে দেয়; কমান্ড কী পাবে তা ক্লায়েন্ট নিয়ন্ত্রণ করে।
samba-usershare-guests = `usershare allow guests` হলো {$value}; ব্যবহারকারীরা এমন শেয়ার প্রকাশ করতে পারে যা যে কেউ পাসওয়ার্ড ছাড়াই খুলতে পারে।
samba-wide-links = `wide links` হলো {$value}; সিম্বলিক লিংক ক্লায়েন্টকে শেয়ারের বাইরে নিয়ে যেতে পারে।

## module template — copy-me example
TEMPLATE-name = মডিউল টেমপ্লেট
TEMPLATE-note-precedence = এই কাল্পনিক মডিউলটি নতুন কনফিগ মডিউলের জন্য কম্পাইল-যাচাই করা একটি উদাহরণ।
TEMPLATE-tip-settings = এই কাল্পনিক মডিউল যে সেটিংগুলো মডেল করে, ফাইলের ক্রমে।
TEMPLATE-tip-key = ডিরেক্টিভের নাম, এক শব্দ, কোনো ফাঁকা স্থান ছাড়া।
TEMPLATE-tip-value = ডিরেক্টিভের মান, লাইনের শেষ পর্যন্ত।
TEMPLATE-rec-value = আপস্ট্রিম ডিফল্টের ওপর নির্ভর না করে স্পষ্ট মান দিন।
TEMPLATE-invalid-key = `{$key}` একটি বৈধ ডিরেক্টিভের নাম নয়।
TEMPLATE-duplicate-key = `{$key}` একাধিকবার সেট করা হয়েছে; শেষ মানটি কার্যকর হয়।
TEMPLATE-too-many-settings = এই ফাইলে {$count}টি সেটিং আছে; বড় কনফিগারেশন ছোট ফাইলে ভাগ করুন।

## detent-core — parse, model, and edit errors
## These are the failures a module's own document model can raise, so they are
## prefixed `core-` rather than with a module id.
core-parse-malformed = এই ফাইল `{$module}` যে ফরম্যাট আশা করে তার সঙ্গে মেলে না: {$reason}
core-model-shape = প্রদত্ত কনফিগারেশন প্রত্যাশিত গঠনের নয়: {$reason}
core-model-unrepresentable = এই ফাইলে এমন কিছু আছে যা সম্পাদক উপস্থাপন করতে পারে না: {$reason}
core-edit-line-break = মানে নতুন লাইন বা null বাইট থাকতে পারে না; `{$value}`-এ আছে।
core-edit-index-out-of-range = অভ্যন্তরীণ ত্রুটি: লাইন {$index} {$len} লাইনের একটি ফাইলের বাইরে।
core-edit-unsupported = এই সম্পাদনা ফাইলের ফরম্যাটে প্রকাশ করা যায় না: {$reason}

## detent-core — version-gated options
core-version-too-old = `{$option}`-এর জন্য {$service} {$since} বা তার পরের সংস্করণ লাগে; এই হোস্টে আছে {$installed}।
core-version-unknown = ইনস্টল করা {$service}-এর সংস্করণ অজানা, তাই `{$option}` ({$service} {$since} বা তার পরের সংস্করণ লাগে) কাজ নাও করতে পারে।

## operations layer — errors surfaced by detent-ops
ops-unknown-module = এই বিল্ডে `{$module}` নামে কোনো মডিউল নেই।
ops-invalid-model = `{$module}`-এর কনফিগারেশন বৈধ নয়: {$reason}
ops-check-failed = বাহ্যিক ভ্যালিডেটর `{$program}` প্রার্থীকে প্রত্যাখ্যান করেছে: {$reason}
ops-hash-conflict = পড়ার পর `{$path}` ডিস্কে বদলে গেছে; এটি আবার পড়ুন এবং পুনরায় চেষ্টা করুন।
ops-privsep-failed = সুবিধাপ্রাপ্ত হেল্পার অনুরোধ প্রত্যাখ্যান করেছে বা সম্পন্ন করতে পারেনি: {$reason}
ops-service-failed = সার্ভিসের কাজ সম্পন্ন হয়নি: {$reason}
ops-no-target = `{$module}` এই হোস্টে কোনো ফাইল পরিচালনা করে না।
ops-no-service = `{$module}` এই হোস্টে কোনো সার্ভিস নিয়ন্ত্রণ করে না, তাই এটি রিস্টার্ট করা যায় না।
ops-audit-failed = অডিট লগ পড়া যায়নি: {$reason}
ops-audit-unavailable = অডিট লগ লেখা যায়নি, তাই অপারেশন প্রত্যাখ্যান করা হয়েছে: {$reason}
ops-unsupported = {$what} এই বিল্ডে সমর্থিত নয়।
ops-commit-pending = আরেকটি commit-confirm উইন্ডো ইতিমধ্যেই অপেক্ষমাণ।
ops-update-running = একটি আপডেট ইতিমধ্যেই চলছে; এটি শেষ হওয়া পর্যন্ত অপেক্ষা করুন, তারপর চলমান সংস্করণ দেখুন।
ops-update-tag-invalid = এটি কোনো রিলিজ সংস্করণ নয়; এটি দেখতে v1.2.3-এর মতো হতে হবে।
ops-update-not-newer = ওই রিলিজ চলমান সংস্করণের চেয়ে নতুন নয়; কিছুই শুরু করা হয়নি।
ops-no-backup = commit-confirm-এর জন্য সংরক্ষিত ব্যাকআপ লাগে; কিছুই বদলানো হয়নি।
ops-arm-failed-restored = commit-confirm সক্রিয় করা যায়নি, তাই পরিবর্তনটি পূর্বাবস্থায় ফেরানো হয়েছে; আগের বিষয়বস্তু ফিরে এসেছে।
ops-arm-failed-unrestored = commit-confirm সক্রিয় করা যায়নি এবং পরিবর্তনটি পূর্বাবস্থায় ফেরানো যায়নি; নতুন বিষয়বস্তু এখনও ডিস্কে আছে। এখনই আগের ব্যাকআপ পুনরুদ্ধার করুন।
ops-target-missing = পরিচালিত ফাইলটি নেই; এটি তৈরি করুন (এর প্যাকেজ ইনস্টল করুন বা হাতে তৈরি করুন), তারপর আবার চেষ্টা করুন।
ops-denied = আপনার এটি করার অনুমতি নেই।

## detent-web — configuration, TLS, the operations bridge, and the listener
web-config-unreadable = `{$path}` পড়া যায়নি: {$reason}
web-config-malformed = `{$path}` একটি বৈধ detent কনফিগারেশন নয়: {$reason}
web-config-zero-value = `{$field}` শূন্যের চেয়ে বড় হতে হবে।
web-config-weak-argon2 = `auth.argon2.m_kib` হলো {$m}, যা ন্যূনতম {$min} kib-এর চেয়ে কম।
web-tls-generate-failed = বুটস্ট্র্যাপ সার্টিফিকেট তৈরি করা যায়নি: {$reason}
web-tls-key-rejected = সার্টিফিকেট ও তার প্রাইভেট কী প্রত্যাখ্যান করা হয়েছে: {$reason}
web-tls-store-unreadable = `{$path}` পড়া যায়নি: {$reason}
web-tls-store-unwritable = `{$path}` লেখার জন্য প্রস্তুত করা যায়নি: {$reason}
web-tls-store-write-failed = `{$path}` লেখা যায়নি: {$reason}
web-tls-acme-pem-rejected = ইস্যু করা সার্টিফিকেট বা কী ব্যবহারযোগ্য PEM ছিল না।
web-engine-stopped = অপারেশন ইঞ্জিন আর চলছে না; সার্ভিস ফিরে এলে আবার চেষ্টা করুন।
web-cert-renew-not-acme = নবায়নের জন্য detent.toml-এ `tls.bootstrap = "acme"` লাগে।
web-cert-renew-unavailable = acme ক্লায়েন্ট নবায়নের অনুরোধ পায়নি; পরে আবার চেষ্টা করুন।
web-update-not-checked = এই হোস্টে এখনও কোনো আপডেট যাচাই চলেনি; root হিসেবে `detent update --check` চালান।
web-server-bind-failed = `{$addr}`-এ শোনা যায়নি: {$reason}
web-server-address-unknown = শোনার ঠিকানা ফেরত পড়া যায়নি: {$reason}

## detent-web — auth: passwords, sessions, api tokens, totp, csrf
web-auth-entropy-unavailable = সিস্টেমের র‍্যান্ডম নম্বর জেনারেটর ব্যর্থ হয়েছে, তাই কোনো ক্রেডেনশিয়াল ইস্যু করা যায়নি।
web-auth-argon2-params = কনফিগার করা argon2 প্যারামিটার ব্যবহারযোগ্য নয়: {$reason}
web-auth-hash-failed = পাসওয়ার্ডের হ্যাশ তৈরি করা যায়নি।
web-auth-password-too-short = পাসওয়ার্ডে কমপক্ষে ১২টি অক্ষর থাকতে হবে।
web-auth-password-too-long = পাসওয়ার্ডে সর্বোচ্চ ১২৮টি অক্ষর থাকতে পারে।
web-auth-password-unchanged = নতুন পাসওয়ার্ড বর্তমান পাসওয়ার্ড থেকে আলাদা হতে হবে।
web-auth-password-change-required = অন্য কিছু করার আগে আপনার পাসওয়ার্ড বদলান।
web-auth-user-name-invalid = `{$name}` ব্যবহারযোগ্য ব্যবহারকারীর নাম নয়; `a-z`, `0-9`, `.`, `_` বা `-` থেকে ১ থেকে ৩২টি অক্ষর ব্যবহার করুন, যা একটি অক্ষর বা অঙ্ক দিয়ে শুরু হবে।
web-auth-user-exists = `{$name}` নামে একজন ব্যবহারকারী ইতিমধ্যে আছেন।
web-auth-user-unknown = `{$name}` নামে কোনো ব্যবহারকারী নেই।
web-auth-invalid-credentials = ব্যবহারকারীর নাম, পাসওয়ার্ড বা কোড সঠিক ছিল না।
web-auth-rate-limited = অনেক বেশি চেষ্টা হয়েছে; {$seconds} সেকেন্ড অপেক্ষা করে আবার চেষ্টা করুন।
web-auth-session-limit = অনেক বেশি সেশন খোলা আছে; একটির মেয়াদ শেষ হওয়া পর্যন্ত অপেক্ষা করে আবার সাইন ইন করুন।
web-auth-busy = অনেক বেশি সাইন-ইন চলছে; একটু অপেক্ষা করে আবার চেষ্টা করুন।
web-auth-unauthenticated = এটি করতে সাইন ইন করুন।
web-auth-ambiguous-credentials = সেশন কুকি অথবা বেয়ারার টোকেন পাঠান, দুটো একসঙ্গে নয়।
web-auth-csrf-rejected = এই অনুরোধ তার ক্রস-সাইট যাচাই পাস করেনি।
web-auth-token-unknown = ওই api টোকেন নেই, বাতিল করা হয়েছে, অথবা মেয়াদোত্তীর্ণ হয়েছে।
web-auth-token-limit = এই হোস্টে ইতিমধ্যেই api টোকেনের সর্বোচ্চ সংখ্যা আছে।
web-auth-totp-secret-invalid = ওই অথেন্টিকেটর সিক্রেট বৈধ base32 নয়।
web-auth-store-unreadable = `{$path}` পড়া যায়নি: {$reason}
web-auth-store-unwritable = `{$path}` লেখার জন্য প্রস্তুত করা যায়নি: {$reason}
web-auth-store-write-failed = `{$path}` লেখা যায়নি: {$reason}
web-auth-store-malformed = `{$path}` একটি বৈধ detent ক্রেডেনশিয়াল ফাইল নয়: {$reason}
web-denied-scope = এই ক্রেডেনশিয়ালে `{$scope}` স্কোপ নেই।

## detent-web — the api surface
web-request-malformed = অনুরোধের বডি এই এন্ডপয়েন্ট যে গঠন আশা করে তার নয়।
web-request-too-deep = অনুরোধের বডি অতিরিক্ত গভীরভাবে নেস্ট করা।
web-api-unexpected-outcome = অপারেশন সম্পন্ন হয়েছে কিন্তু তার ফলাফল প্রদর্শন করা যায়নি।
