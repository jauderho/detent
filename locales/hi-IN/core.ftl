# needs-review: machine-drafted Hindi translation; not yet checked by a native speaker.
## detent-core — hi
## Source: locales/en-US/core.ftl. Same ids, same placeables. Code-like tokens
## (directive names, paths, flags, option values) stay untranslated.

## chrony module — display name, security notes, schema tooltips
chrony-name = chrony
chrony-note-precedence = यह फ़ाइल कंपाइल किए गए डिफ़ॉल्ट मानों को ओवरराइड करती है; गलत मान चुपचाप बदल देता है कि होस्ट समय कैसे रखता है।
chrony-tip-settings = chrony.conf के वे डायरेक्टिव जिन्हें यह मॉड्यूल मॉडल करता है, फ़ाइल के क्रम में; फ़ाइल में बाकी सब कुछ जस का तस सुरक्षित रहता है।
chrony-tip-key = डायरेक्टिव का नाम, एक शब्द, अक्षर-भेद रहित।
chrony-tip-value = इस डायरेक्टिव का मान, पंक्ति के अंत तक; `rtcsync` जैसे मान-रहित डायरेक्टिव के लिए खाली।
chrony-rec-value = कंपाइल किए गए डिफ़ॉल्ट पर निर्भर रहने के बजाय स्पष्ट मान दें।

## chrony module — validation diagnostics
chrony-privileged-directive = `{$key}` वह फ़ाइल सेट करता है जिसे chronyd root के रूप में लिखता है, या वह उपयोगकर्ता जिसके रूप में वह चलता है। लागू करने से पहले मान जाँच लें।
chrony-invalid-key = `{$key}` मान्य chrony डायरेक्टिव नाम नहीं है।
chrony-duplicate-key = `{$key}` एक से अधिक बार सेट है; आख़िरी मान प्रभावी होता है।
chrony-too-many-settings = इस फ़ाइल में {$count} सेटिंग हैं; इसे /etc/chrony/conf.d के अंतर्गत ड्रॉप-इन फ़ाइलों में बाँट दें।
chrony-allow-open = `allow {$value}` पूरे इंटरनेट को समय उपलब्ध कराता है; केवल उन्हीं नेटवर्क को अनुमति दें जिन्हें इसकी ज़रूरत है।
chrony-missing-makestep = makestep सेट नहीं है; स्टार्टअप पर घड़ी को सीमा में लाने के बजाय वह असीमित रूप से खिसक सकती है।
chrony-missing-rtcsync = rtcsync सेट नहीं है; हार्डवेयर घड़ी सिस्टम घड़ी के सापेक्ष खिसकती जाएगी।
chrony-rec-nts = पूल {$pool} nts विकल्प के बिना उपयोग हो रहा है; nts-सक्षम स्रोत चुनें ताकि समय की स्पूफ़िंग न हो सके।
chrony-cmdport-open = cmdport {$port} है; जब तक chronyc को इस होस्ट तक नेटवर्क से पहुँचना आवश्यक न हो, cmdport 0 सेट करें।
chrony-external-directive = `{$key}` बाहरी फ़ाइलें लोड करता है या बाहरी प्रोग्राम चलाता है; यह मॉड्यूल उन डायरेक्टिव को अस्वीकार करता है जो उसकी तय फ़ाइल-सीमा को पार करते हैं।

## dhcp module — display name, security notes, schema tooltips
dhcp-name = dhcp
dhcp-note-commit-confirm = DHCP में गलत बदलाव हर क्लाइंट को, और आपको भी, नेटवर्क से काट देता है; पुष्टि करने से पहले diff ध्यान से जाँच लें।
dhcp-tip-dnsmasq = /etc/dnsmasq.conf की `key=value` सेटिंग, फ़ाइल के क्रम में; टिप्पणियाँ और अज्ञात पंक्तियाँ जस की तस सुरक्षित रहती हैं।
dhcp-tip-kea-v4 = Kea DHCPv4 सर्वर (`Dhcp4`) का प्रबंधित उपसमूह; अज्ञात Kea विकल्प जस के तस सुरक्षित रहते हैं।
dhcp-tip-kea-v6 = Kea DHCPv6 सर्वर (`Dhcp6`) का प्रबंधित उपसमूह; अज्ञात Kea विकल्प जस के तस सुरक्षित रहते हैं।
dhcp-tip-key = dnsmasq विकल्प का नाम, एक शब्द, बिना रिक्त स्थान के।
dhcp-tip-value = `=` के बाद का मान; `domain-needed` जैसे अकेले फ़्लैग का कोई मान नहीं होता।
dhcp-tip-interfaces = वे इंटरफ़ेस जिन पर Kea सर्वर सुनता है; खाली सूची का अर्थ है कि सर्वर हर इंटरफ़ेस पर उत्तर देता है।
dhcp-tip-valid-lifetime = सेकंड में डिफ़ॉल्ट लीज़ अवधि; अधिकांश नेटवर्क के लिए 3600 उचित डिफ़ॉल्ट है।
dhcp-tip-subnets = वे सबनेट जिनसे सर्वर पते आवंटित करता है।
dhcp-tip-id = Kea का स्थिर सबनेट पहचानकर्ता; संपादन में इसे स्थिर रखें, लीज़ इसी से जुड़ी होती हैं।
dhcp-tip-subnet = CIDR रूप में सबनेट प्रीफ़िक्स, जैसे `192.168.1.0/24`।
dhcp-tip-pools = सबनेट के डायनामिक पता पूल।
dhcp-tip-routers = क्लाइंट को दिया जाने वाला राउटर (डिफ़ॉल्ट गेटवे) विकल्प।
dhcp-tip-domain-servers = क्लाइंट को दिए जाने वाले DNS सर्वर (`domain-name-servers`)।
dhcp-tip-pool = पूल, रेंज `192.168.1.100 - 192.168.1.200` या प्रीफ़िक्स `192.168.1.0/24` के रूप में।

## dhcp module — validation diagnostics
dhcp-empty-key = किसी dnsmasq सेटिंग का विकल्प नाम खाली है।
dhcp-invalid-key = `{$key}` मान्य dnsmasq विकल्प नाम नहीं है; यह रिक्त स्थान, `=` या `#` के बिना एक शब्द होना चाहिए।
dhcp-malformed-cidr = `{$value}` मान्य CIDR प्रीफ़िक्स नहीं है, जैसे `192.168.1.0/24`।
dhcp-malformed-pool = `{$value}` मान्य पूल नहीं है; `192.168.1.100 - 192.168.1.200` जैसी रेंज या CIDR प्रीफ़िक्स का उपयोग करें।
dhcp-external-directive = `{$key}` बाहरी फ़ाइलें लोड करता है या कमांड चलाता है; यह मॉड्यूल ऐसे डायरेक्टिव नहीं बनाएगा या बदलेगा जो उसकी तय फ़ाइल-सीमा को पार करते हैं।
dhcp-authoritative-set = `dhcp-authoritative` dnsmasq को उस सेगमेंट का एकमात्र DHCP सर्वर बना देता है; इसे तभी सेट करें जब कोई अन्य DHCP सर्वर न हो।
dhcp-kea-interfaces-empty = {$server} में कोई इंटरफ़ेस कॉन्फ़िगर नहीं है और वह हर इंटरफ़ेस पर सुनेगा; इंटरफ़ेस के नाम स्पष्ट रूप से दें।
dhcp-rec-rebind = domain-needed और bogus-priv दोनों सेट नहीं हैं; वे रीबाइंड हमलों और निजी पतों के लिए अपस्ट्रीम A क्वेरी को फ़िल्टर करते हैं।
dhcp-rec-lifetime = {$server} का valid-lifetime {$lifetime} है; इसे 300 से 86400 सेकंड के बीच रखें ताकि लीज़ अनुमानित रूप से नवीनीकृत हों।

## hosts module — display name, security notes, schema tooltips
hosts-name = hosts
hosts-note-spoofing = यहाँ की प्रविष्टियाँ DNS को ओवरराइड करती हैं; गलत या दुर्भावनापूर्ण प्रविष्टि चुपचाप लुकअप को कहीं और भेज देती है।
hosts-tip-entries = /etc/hosts में पते-से-नाम के मैपिंग, फ़ाइल के क्रम में।
hosts-tip-ip = वह पता जिस पर नीचे दिए नाम रिज़ॉल्व होते हैं।
hosts-tip-hostnames = वे नाम जो इस पते पर रिज़ॉल्व होते हैं, पहले कैननिकल नाम।
hosts-tip-comment = इस प्रविष्टि की इनलाइन टिप्पणी, यदि कोई हो।

## hosts module — validation diagnostics
hosts-invalid-hostname = `{$name}` मान्य होस्टनाम नहीं है।
hosts-duplicate-canonical = `{$name}` एक से अधिक प्रविष्टियों का कैननिकल नाम है।
hosts-no-hostnames = इस प्रविष्टि में कोई होस्टनाम नहीं है।
hosts-hostname-is-ip = `{$name}` एक पता है, होस्टनाम नहीं।
hosts-ipv6-zone-unsupported = `{$name}` में ipv6 ज़ोन आईडी है, जिसे /etc/hosts समर्थित नहीं करता।
hosts-hostname-multiple-ips = `{$name}` एक ही परिवार के एक से अधिक पतों पर रिज़ॉल्व होता है।
hosts-localhost-not-loopback = `localhost` `{$ip}` की ओर इशारा करता है, जो लूपबैक पता नहीं है।
hosts-missing-localhost = कोई `localhost` प्रविष्टि नहीं है।
hosts-missing-ipv6-localhost = कोई ipv6 `localhost` प्रविष्टि नहीं है।
hosts-too-many-entries = इस फ़ाइल में {$count} प्रविष्टियाँ हैं; इसके बजाय DNS पर विचार करें।

## mounts module — display name, security notes, schema tooltips
mounts-name = mounts
mounts-note-boot = गलत /etc/fstab अगले रीस्टार्ट पर होस्ट को बूट न होने योग्य छोड़ सकता है; हर बदलाव के लिए दूसरी पुष्टि ज़रूरी है। पुष्टि गलत प्रविष्टि नहीं पकड़ सकती, क्योंकि अगले बूट से पहले कोई भी फ़ाइल को नहीं पढ़ता।
mounts-tip-entries = /etc/fstab में माउंट प्रविष्टियाँ, फ़ाइल के क्रम में।
mounts-tip-spec = क्या माउंट हो रहा है: कोई डिवाइस, `UUID=...`/`LABEL=...`, कोई nfs एक्सपोर्ट, या स्वैप के लिए `none`।
mounts-tip-mountpoint = फ़ाइल सिस्टम कहाँ माउंट होता है, या स्वैप के लिए `none`/`swap`।
mounts-tip-fstype = फ़ाइल सिस्टम का प्रकार, जैसे ext4, या `swap`।
mounts-tip-options = अल्पविराम से अलग किए गए माउंट विकल्प, जैसे defaults,nosuid।
mounts-tip-dump = dump(8) बैकअप की आवृत्ति; लगभग हमेशा 0।
mounts-tip-pass = fsck पास संख्या: root के लिए 1, जाँचे जाने वाले अन्य फ़ाइल सिस्टम के लिए 2, छोड़ने के लिए 0।
mounts-rec-options = उपयोगकर्ता-लिखने योग्य डेटा को nosuid, nodev और noexec से सुरक्षित करें; नेटवर्क फ़ाइल सिस्टम पर x-systemd.automount को प्राथमिकता दें।

## mounts module — validation diagnostics
mounts-empty-spec = प्रविष्टि {$index} का spec (पहला कॉलम) खाली है।
mounts-empty-mountpoint = प्रविष्टि {$index} का माउंट पॉइंट (दूसरा कॉलम) खाली है।
mounts-invalid-fstype = `{$fstype}` मान्य फ़ाइल सिस्टम प्रकार नहीं है।
mounts-pass-too-high = प्रविष्टि {$index} का pass `{$pass}` है; fsck अधिकतम 2 पास चलाता है।
mounts-root-pass = root फ़ाइल सिस्टम का pass 1 होना चाहिए, `{$pass}` नहीं।
mounts-missing-nofail = `{$mountpoint}` बिना `nofail` के रिमूवेबल मीडिया है; इसे निकाल देने पर बूट अटक जाता है।
mounts-missing-boot-escape = `{$mountpoint}` में न nofail है न noauto; माउंट विफल होने पर बूट रुक सकता है।
mounts-critical-noauto = `{$mountpoint}` बूट के लिए ज़रूरी है पर उसमें noauto है, इसलिए सिस्टम उसके बिना आगे बढ़ सकता है।
mounts-missing-guards = `{$mountpoint}` उपयोगकर्ता-लिखने योग्य डेटा बिना `{$missing}` के माउंट करता है; इन्हें जोड़ें।
mounts-network-automount = `{$mountpoint}` बिना `x-systemd.automount` का नेटवर्क फ़ाइल सिस्टम है; बूट नेटवर्क की प्रतीक्षा करता है।
mounts-noauto-without-user = `user` के बिना `noauto`: इसे केवल root माउंट कर सकता है, जिससे इसका उद्देश्य ही विफल हो जाता है।
mounts-relative-mountpoint = प्रविष्टि {$index} `{$mountpoint}` पर माउंट होती है, जो निरपेक्ष पथ नहीं है।
mounts-no-root-entry = कोई प्रविष्टि `/` को माउंट नहीं करती; जाँच लें कि root फ़ाइल सिस्टम किसी और तरीके से माउंट होता है।

## network module — display name, security notes, schema tooltips
network-name = network
network-note-precedence = गलत नेटवर्क कॉन्फ़िगरेशन व्यवस्थापक को इस होस्ट से काट सकता है; हर बदलाव के लिए दूसरी पुष्टि ज़रूरी है।
network-tip-interfaces = वे इंटरफ़ेस जिन्हें यह होस्ट कॉन्फ़िगर करता है, फ़ाइल के क्रम में।
network-tip-iface-name = इंटरफ़ेस का नाम, जैसे eth0।
network-tip-iface-dhcp-v4 = क्या इस इंटरफ़ेस को अपना IPv4 पता DHCP से मिलता है।
network-tip-iface-dhcp-v6 = क्या इस इंटरफ़ेस को अपना IPv6 पता DHCP से मिलता है।
network-tip-iface-addresses = CIDR संकेतन में स्थिर पते, जैसे 192.168.1.10/24।
network-tip-iface-gateway-v4 = IPv4 के लिए डिफ़ॉल्ट गेटवे, जब पता स्थिर हो।
network-tip-iface-gateway-v6 = IPv6 के लिए डिफ़ॉल्ट गेटवे, जब पता स्थिर हो।
network-tip-iface-dns = इस इंटरफ़ेस के लिए DNS सर्वर।
network-tip-iface-routes = इस इंटरफ़ेस के लिए स्थिर रूट।
network-tip-iface-vlan = इस इंटरफ़ेस की VLAN सेटिंग, जब यह VLAN हो।
network-tip-iface-bridge = इस इंटरफ़ेस की ब्रिज सेटिंग, जब यह ब्रिज हो।
network-tip-route-to = गंतव्य CIDR या default।
network-tip-route-via = नेक्स्ट-हॉप IP।
network-tip-vlan-link = इस VLAN का पैरेंट लिंक, जैसे eth0।
network-tip-vlan-id = VLAN आईडी, 1–4094।
network-tip-bridge-members = इस ब्रिज के सदस्य इंटरफ़ेस के नाम।

## network module — validation diagnostics
network-invalid-cidr = `{$value}` मान्य CIDR पता नहीं है।
network-invalid-ip = `{$value}` मान्य IP पता नहीं है।
network-gateway-outside-subnet = गेटवे `{$gateway}` इस इंटरफ़ेस के सबनेट के बाहर है।
network-vlan-range = VLAN आईडी `{$id}` 1–4094 के बाहर है।
network-duplicate-interface = इंटरफ़ेस `{$name}` एक से अधिक बार आता है।
network-interface-order = इंटरफ़ेस `{$name}` अपने ऊपर के इंटरफ़ेस से पहले आना चाहिए: इंटरफ़ेस को नाम के क्रम में सूचीबद्ध करें।
network-injection = `{$value}` में नई पंक्ति या null बाइट है।
network-static-no-gateway = इस स्थिर पते वाले इंटरफ़ेस में कोई गेटवे नहीं है।
network-static-no-dns = इस स्थिर पते वाले इंटरफ़ेस में कोई DNS सर्वर नहीं है।
network-dhcp-static-mixed = इस इंटरफ़ेस में DHCP और स्थिर पते दोनों हैं।
network-rec-ipv6-privacy = DHCPv6 चालू होने पर IPv6 प्राइवेसी एक्सटेंशन चालू करें।
network-rec-ra-accept = राउटर एडवर्टाइज़मेंट तभी स्वीकारें जब DHCPv6 स्पष्ट रूप से प्रबंधित हो।
network-rec-no-promisc = इस इंटरफ़ेस को प्रोमिस्क्यूअस मोड में नहीं चलना चाहिए।

## nfs module — display name, security notes, schema tooltips
nfs-name = nfs
nfs-note-live-state = एक्सपोर्ट कर्नेल द्वारा हर माउंट पर लागू किए जाते हैं; गलत पंक्ति चुपचाप बदल देती है कि कौन-से होस्ट कौन-से फ़ाइल सिस्टम पढ़ सकते हैं।
nfs-tip-entries = /etc/exports में एक्सपोर्ट, फ़ाइल के क्रम में।
nfs-tip-path = एक्सपोर्ट पॉइंट: इस होस्ट पर निरपेक्ष डायरेक्टरी पथ।
nfs-tip-clients = वे होस्ट जिन्हें यह एक्सपोर्ट माउंट करने की अनुमति है, मिलान के क्रम में; पहला मिलने वाला विनिर्देश प्रभावी होता है।
nfs-tip-host = क्लाइंट विनिर्देश: नाम, पता, पता/नेटमास्क, वाइल्डकार्ड, `*` (हर क्लाइंट), या @netgroup।
nfs-tip-options = इस क्लाइंट के एक्सपोर्ट विकल्प, अल्पविराम से अलग; खाली सूची फ़ाइल के डिफ़ॉल्ट लेती है।
nfs-rec-options = rw/ro, sync/async, root_squash और subtree का व्यवहार स्पष्ट रूप से लिखें; डिफ़ॉल्ट nfs-utils रिलीज़ के बीच बदलते रहते हैं।

## nfs module — validation diagnostics
nfs-empty-path = एक एक्सपोर्ट पॉइंट खाली है।
nfs-relative-path = `{$path}` निरपेक्ष नहीं है; एक्सपोर्ट पॉइंट `/` से शुरू होना चाहिए।
nfs-empty-host = `{$path}` के एक क्लाइंट का कोई होस्ट विनिर्देश नहीं है।
nfs-bad-host = `{$host}` मान्य क्लाइंट विनिर्देश नहीं है; वह `-` से शुरू होता है या उसमें ऐसा सिंटैक्स है जो पंक्ति को काट देगा।
nfs-bad-path = `{$path}` में ऐसा सिंटैक्स है जो एक्सपोर्ट पंक्ति को काट देगा।
nfs-bad-continuation = `{$path}` का अंत निरंतरता बैकस्लैश पर होगा और अगली पंक्ति को जोड़ लेगा।
nfs-invalid-option = `{$option}` मान्य एक्सपोर्ट विकल्प नहीं है; विकल्प बिना रिक्त स्थान या कोष्ठक के सादे टोकन होते हैं।
nfs-no-root-squash = `{$host}` no_root_squash के साथ माउंट करता है और एक्सपोर्ट पर root अधिकार बनाए रखता है।
nfs-sec-sys-only = `{$host}` डिफ़ॉल्ट sec=sys का उपयोग करता है या केवल sec=sys पर सहमत होता है; क्रिप्टोग्राफ़िक सुरक्षा के लिए krb5p जोड़ें।
nfs-world-export = `{$host}` हर क्लाइंट के लिए पढ़ने-लिखने हेतु पहुँच योग्य है।
nfs-subtree-undecided = `{$host}` में न subtree_check है न no_subtree_check; अपस्ट्रीम ने डिफ़ॉल्ट बदल दिया है, इसलिए बताएँ कि आप कौन-सा चाहते हैं।
nfs-root-squash-undecided = `{$host}` में न root_squash है न no_root_squash; बताएँ कि आप कौन-सा चाहते हैं।
nfs-sync-undecided = `{$host}` में न sync है न async; sync को प्राथमिकता दें, जो लेखन को स्थिर संग्रहण में कमिट करता है।

## resolver module — display name, security notes, schema tooltips
resolver-name = resolver
resolver-note-managed-symlink = इस होस्ट पर /etc/resolv.conf को एक रिज़ॉल्वर बैकएंड प्रबंधित करता है; detent प्रबंधित सिमलिंक के लक्ष्य को संपादित करने से मना करता है और इसके बजाय बैकएंड को कॉन्फ़िगर करता है।
resolver-tip-resolv = /etc/resolv.conf के वे डायरेक्टिव जिन्हें यह मॉड्यूल मॉडल करता है; फ़ाइल में बाकी सब कुछ जस का तस सुरक्षित रहता है।
resolver-tip-resolved = systemd-resolved की सेटिंग, फ़ाइल के क्रम में। इन्हें बदलने से systemd-resolved रीस्टार्ट होता है।
resolver-tip-unbound = unbound.conf के वे आइटम जिन्हें यह मॉड्यूल मॉडल करता है, फ़ाइल के क्रम में। इन्हें बदलने से unbound रीस्टार्ट होता है।

## resolver module — validation diagnostics
resolver-no-nameserver = कोई nameserver कॉन्फ़िगर नहीं है।
resolver-duplicate-nameserver = `{$ip}` एक से अधिक nameserver के रूप में आता है।
resolver-too-many-nameservers = इस फ़ाइल में {$count} nameserver सूचीबद्ध हैं; glibc अधिकतम {$max} पढ़ता है।
resolver-invalid-domain = `{$domain}` मान्य डोमेन नाम नहीं है।
resolver-unknown-option = `{$option}` glibc के resolv.conf पार्सर द्वारा स्वीकार किया जाने वाला विकल्प नहीं है।
resolver-search-and-domain = `search` और `domain` दोनों मौजूद हैं; `search` सेट होने पर glibc `domain` को अनदेखा करता है।
resolver-no-config = यह मॉडल कोई भी रिज़ॉल्वर बैकएंड कॉन्फ़िगर नहीं करता।
resolver-backend-missing = ये सेटिंग {$service} को कॉन्फ़िगर करती हैं, जो इस होस्ट पर नहीं मिला।
resolver-rec-dnssec = DNSSEC allow-downgrade पर सेट है; `DNSSEC=yes` सख़्ती से सत्यापित करता है और जहाँ अपस्ट्रीम डेटा अनुमति दे वहाँ अनुशंसित है।
resolver-rec-dot = DNSOverTLS अवसरवादी है, जो सादे पाठ पर डाउनग्रेड हो जाता है; `DNSOverTLS=yes` इसके बजाय TLS अनिवार्य करता है।
resolver-unknown-hardening = `{$key}` ऐसा डायरेक्टिव नहीं है जिसे यह मॉड्यूल unbound के लिए मॉडल करता है।
resolver-unbound-misplaced = `{$key}` unbound.conf के {$section} सेक्शन का है, यहाँ का नहीं।
resolver-invalid-forward-addr = `{$addr}` ip[@port][#auth-name] रूप का मान्य forward-addr नहीं है।
resolver-invalid-forward-name = `{$name}` मान्य forward-zone नाम नहीं है।
resolver-forward-tls-no-auth = यह ज़ोन अपने forward-addr पर `#auth-name` के बिना TLS से फ़ॉरवर्ड करता है, इसलिए TLS कनेक्शन प्रमाणित नहीं है।
resolver-rec-hardening = `{$key}` बंद है; इसे चालू करने से unbound अपस्ट्रीम स्पूफ़िंग और डेलीगेशन के दुरुपयोग से सख़्त होता है।
resolver-forward-zone-unnamed = बिना name: वाला forward-zone: कुछ भी फ़ॉरवर्ड नहीं करता और कॉन्फ़िगरेशन को कमज़ोर करता है; हर ज़ोन को नाम दें।

## samba module — display name, security notes, schema tooltips
samba-name = samba
samba-note-guest-access = अतिथि पहुँच कनेक्शन के समय प्रति शेयर दी जाती है; गलत मान बिना पासवर्ड के फ़ाइलें उजागर कर देता है।
samba-tip-entries = smb.conf की वे प्रविष्टियाँ जिन्हें यह मॉड्यूल मॉडल करता है, फ़ाइल के क्रम में: `[section]` हेडर और डायरेक्टिव दोनों।
samba-tip-section = `[section]` हेडर के लिए सेक्शन का नाम; सादी डायरेक्टिव पंक्ति के लिए खाली।
samba-tip-key = पैरामीटर का नाम, अक्षर-भेद रहित और संभवतः बहु-शब्द (`guest ok`)।
samba-tip-value = पैरामीटर का मान, पंक्ति के अंत तक; `%` मैक्रो ज्यों के त्यों सुरक्षित रहते हैं।
samba-rec-value = अपस्ट्रीम के कंपाइल किए गए डिफ़ॉल्ट पर निर्भर रहने के बजाय स्पष्ट रूप से सख़्त मान दें।

## samba module — validation diagnostics
samba-empty-key = किसी डायरेक्टिव का कोई पैरामीटर नाम नहीं है।
samba-empty-section = एक सेक्शन हेडर खाली है।
samba-bad-key = `{$key}` को सेक्शन या टिप्पणी के रूप में पार्स किया जाएगा, डायरेक्टिव कुंजी के रूप में नहीं।
samba-bad-value = `{$value}` का अंत `\` पर होता है और वह अगली पंक्ति को निगल लेगा।
samba-bad-section = `{$section}` में `[` या `]` है या उसका अंत `\` पर होता है, और वह राउंड-ट्रिप नहीं करेगा।
samba-guest-ok = `guest ok` {$value} पर सेट है; अप्रमाणित क्लाइंट हर उस शेयर से कनेक्ट कर सकते हैं जो इसे विरासत में लेता है।
samba-map-to-guest = `map to guest` {$value} है; Never के अलावा कुछ भी विफल लॉगिन को अतिथि सत्र में बदल देता है।
samba-min-protocol = `server min protocol` {$value} है; कम से कम SMB3_00 सेट करें और SMB1-युग के प्रोटोकॉल स्तर हटाएँ।
samba-smb-encrypt = `smb encrypt` {$value} है; required सेट करें ताकि SMB ट्रैफ़िक अनएन्क्रिप्टेड न जा सके।
samba-restrict-anonymous = `restrict anonymous` {$value} है; 2 शेयर सूची को अनाम उपयोगकर्ताओं से छिपाता है।
samba-rec-server-signing = `server signing` {$value} है; mandatory सेट करें ताकि SMB ट्रैफ़िक पर क्रिप्टोग्राफ़िक हस्ताक्षर हों।
samba-rec-load-printers = `load printers` {$value} है; no सेट करें, जब तक यह होस्ट वास्तव में प्रिंटर साझा न करता हो।
samba-rec-interfaces = कोई `interfaces` डायरेक्टिव सेट नहीं है; samba को हर इंटरफ़ेस पर सुनने देने के बजाय स्पष्ट पतों से बाँधें।
samba-writable-exposure = यह शेयर writeable, read only या write list के माध्यम से लेखन की अनुमति देता है; पुष्टि करें कि हर क्लाइंट को लेखन पहुँच मिलनी चाहिए।
samba-root-command = `{$key}` हर मेल खाने वाले कनेक्शन पर root अधिकारों के साथ कमांड चलाता है।
samba-client-command = `{$key}` क्लाइंट को samba से कमांड चलवाने देता है; कमांड को क्या मिलता है यह क्लाइंट तय करता है।
samba-usershare-guests = `usershare allow guests` {$value} है; उपयोगकर्ता ऐसे शेयर प्रकाशित कर सकते हैं जिन्हें कोई भी बिना पासवर्ड के खोल सकता है।
samba-wide-links = `wide links` {$value} है; सिम्बॉलिक लिंक क्लाइंट को शेयर से बाहर ले जा सकते हैं।

## module template — copy-me example
TEMPLATE-name = मॉड्यूल टेम्पलेट
TEMPLATE-note-precedence = यह काल्पनिक मॉड्यूल नए कॉन्फ़िग मॉड्यूल के लिए कंपाइल-जाँचा हुआ उदाहरण है।
TEMPLATE-tip-settings = वे सेटिंग जिन्हें यह काल्पनिक मॉड्यूल मॉडल करता है, फ़ाइल के क्रम में।
TEMPLATE-tip-key = डायरेक्टिव का नाम, एक शब्द, बिना रिक्त स्थान के।
TEMPLATE-tip-value = डायरेक्टिव का मान, पंक्ति के अंत तक।
TEMPLATE-rec-value = अपस्ट्रीम डिफ़ॉल्ट पर निर्भर रहने के बजाय स्पष्ट मान दें।
TEMPLATE-invalid-key = `{$key}` मान्य डायरेक्टिव नाम नहीं है।
TEMPLATE-duplicate-key = `{$key}` एक से अधिक बार सेट है; आख़िरी मान प्रभावी होता है।
TEMPLATE-too-many-settings = इस फ़ाइल में {$count} सेटिंग हैं; बड़े कॉन्फ़िगरेशन को छोटी फ़ाइलों में बाँट दें।

## detent-core — parse, model, and edit errors
## These are the failures a module's own document model can raise, so they are
## prefixed `core-` rather than with a module id.
core-parse-malformed = यह फ़ाइल उस प्रारूप से मेल नहीं खाती जिसकी `{$module}` अपेक्षा करता है: {$reason}
core-model-shape = दिया गया कॉन्फ़िगरेशन अपेक्षित आकार का नहीं है: {$reason}
core-model-unrepresentable = इस फ़ाइल में कुछ ऐसा है जिसे संपादक प्रस्तुत नहीं कर सकता: {$reason}
core-edit-line-break = मान में नई पंक्ति या null बाइट नहीं हो सकती; `{$value}` में है।
core-edit-index-out-of-range = आंतरिक त्रुटि: पंक्ति {$index} {$len} पंक्तियों की फ़ाइल के बाहर है।
core-edit-unsupported = यह संपादन फ़ाइल के प्रारूप में व्यक्त नहीं किया जा सकता: {$reason}

## detent-core — version-gated options
core-version-too-old = `{$option}` के लिए {$service} {$since} या उससे नया चाहिए; इस होस्ट पर {$installed} है।
core-version-unknown = इंस्टॉल किए गए {$service} का संस्करण अज्ञात है, इसलिए `{$option}` ({$service} {$since} या उससे नया चाहिए) शायद काम न करे।

## operations layer — errors surfaced by detent-ops
ops-unknown-module = इस बिल्ड में `{$module}` नाम का कोई मॉड्यूल नहीं है।
ops-invalid-model = `{$module}` का कॉन्फ़िगरेशन मान्य नहीं है: {$reason}
ops-check-failed = बाहरी वैलिडेटर `{$program}` ने उम्मीदवार को अस्वीकार कर दिया: {$reason}
ops-hash-conflict = `{$path}` पढ़े जाने के बाद डिस्क पर बदल गया; इसे फिर से पढ़ें और दोबारा प्रयास करें।
ops-privsep-failed = विशेषाधिकार प्राप्त हेल्पर ने अनुरोध अस्वीकार कर दिया या पूरा नहीं कर सका: {$reason}
ops-service-failed = सेवा की कार्रवाई पूरी नहीं हुई: {$reason}
ops-no-target = `{$module}` इस होस्ट पर कोई फ़ाइल प्रबंधित नहीं करता।
ops-no-service = `{$module}` इस होस्ट पर कोई सेवा नियंत्रित नहीं करता, इसलिए उसे रीस्टार्ट नहीं किया जा सकता।
ops-audit-failed = ऑडिट लॉग पढ़ा नहीं जा सका: {$reason}
ops-audit-unavailable = ऑडिट लॉग लिखा नहीं जा सका, इसलिए ऑपरेशन अस्वीकार कर दिया गया: {$reason}
ops-unsupported = {$what} इस बिल्ड में समर्थित नहीं है।
ops-commit-pending = एक और commit-confirm विंडो पहले से लंबित है।
ops-update-running = अपडेट पहले से चल रहा है; उसके पूरा होने तक प्रतीक्षा करें, फिर चल रहा संस्करण जाँचें।
ops-update-tag-invalid = यह रिलीज़ संस्करण नहीं है; यह v1.2.3 जैसा दिखना चाहिए।
ops-update-not-newer = वह रिलीज़ चल रहे संस्करण से नई नहीं है; कुछ शुरू नहीं किया गया।
ops-no-backup = commit-confirm के लिए रखा हुआ बैकअप चाहिए; कुछ भी नहीं बदला गया।
ops-arm-failed-restored = commit-confirm सक्रिय नहीं किया जा सका, इसलिए बदलाव पूर्ववत कर दिया गया; पिछली सामग्री वापस आ गई है।
ops-arm-failed-unrestored = commit-confirm सक्रिय नहीं किया जा सका और बदलाव पूर्ववत नहीं किया जा सका; नई सामग्री अब भी डिस्क पर है। अभी पिछला बैकअप पुनर्स्थापित करें।
ops-target-missing = प्रबंधित फ़ाइल मौजूद नहीं है; इसे बनाएँ (इसका पैकेज इंस्टॉल करें या हाथ से बनाएँ), फिर दोबारा प्रयास करें।
ops-denied = आपको ऐसा करने की अनुमति नहीं है।

## detent-web — configuration, TLS, the operations bridge, and the listener
web-config-unreadable = `{$path}` पढ़ा नहीं जा सका: {$reason}
web-config-malformed = `{$path}` मान्य detent कॉन्फ़िगरेशन नहीं है: {$reason}
web-config-zero-value = `{$field}` शून्य से अधिक होना चाहिए।
web-config-weak-argon2 = `auth.argon2.m_kib` {$m} है, जो न्यूनतम {$min} kib से कम है।
web-tls-generate-failed = बूटस्ट्रैप प्रमाणपत्र बनाया नहीं जा सका: {$reason}
web-tls-key-rejected = प्रमाणपत्र और उसकी निजी कुंजी अस्वीकार कर दिए गए: {$reason}
web-tls-store-unreadable = `{$path}` पढ़ा नहीं जा सका: {$reason}
web-tls-store-unwritable = `{$path}` को लिखने के लिए तैयार नहीं किया जा सका: {$reason}
web-tls-store-write-failed = `{$path}` लिखा नहीं जा सका: {$reason}
web-tls-acme-pem-rejected = जारी किया गया प्रमाणपत्र या कुंजी उपयोग योग्य PEM नहीं थी।
web-engine-stopped = ऑपरेशन इंजन अब नहीं चल रहा; सेवा लौटने पर फिर प्रयास करें।
web-cert-renew-not-acme = नवीनीकरण के लिए detent.toml में `tls.bootstrap = "acme"` चाहिए।
web-cert-renew-unavailable = acme क्लाइंट को नवीनीकरण का अनुरोध नहीं मिला; बाद में फिर प्रयास करें।
web-update-not-checked = इस होस्ट पर अभी तक कोई अपडेट जाँच नहीं चली है; root के रूप में `detent update --check` चलाएँ।
web-server-bind-failed = `{$addr}` पर सुना नहीं जा सका: {$reason}
web-server-address-unknown = सुनने वाला पता वापस पढ़ा नहीं जा सका: {$reason}

## detent-web — auth: passwords, sessions, api tokens, totp, csrf
web-auth-entropy-unavailable = सिस्टम का रैंडम नंबर जनरेटर विफल रहा, इसलिए कोई क्रेडेंशियल जारी नहीं किया जा सका।
web-auth-argon2-params = कॉन्फ़िगर किए गए argon2 पैरामीटर उपयोग योग्य नहीं हैं: {$reason}
web-auth-hash-failed = पासवर्ड का हैश नहीं बनाया जा सका।
web-auth-password-too-short = पासवर्ड में कम से कम 12 वर्ण होने चाहिए।
web-auth-password-too-long = पासवर्ड में अधिकतम 128 वर्ण हो सकते हैं।
web-auth-password-unchanged = नया पासवर्ड मौजूदा पासवर्ड से अलग होना चाहिए।
web-auth-password-change-required = कुछ भी और करने से पहले अपना पासवर्ड बदलें।
web-auth-user-name-invalid = `{$name}` उपयोग योग्य उपयोगकर्ता नाम नहीं है; `a-z`, `0-9`, `.`, `_` या `-` के 1 से 32 वर्ण उपयोग करें, जो किसी अक्षर या अंक से शुरू हों।
web-auth-user-exists = `{$name}` नाम का उपयोगकर्ता पहले से मौजूद है।
web-auth-user-unknown = `{$name}` नाम का कोई उपयोगकर्ता नहीं है।
web-auth-invalid-credentials = उपयोगकर्ता नाम, पासवर्ड या कोड सही नहीं था।
web-auth-rate-limited = बहुत अधिक प्रयास; {$seconds} सेकंड प्रतीक्षा करें और फिर प्रयास करें।
web-auth-session-limit = बहुत अधिक सत्र खुले हैं; किसी के समाप्त होने की प्रतीक्षा करें और फिर साइन इन करें।
web-auth-busy = बहुत अधिक साइन-इन चल रहे हैं; थोड़ी देर प्रतीक्षा करें और फिर प्रयास करें।
web-auth-unauthenticated = ऐसा करने के लिए साइन इन करें।
web-auth-ambiguous-credentials = या तो सत्र कुकी भेजें या बेयरर टोकन, दोनों नहीं।
web-auth-csrf-rejected = यह अनुरोध अपनी क्रॉस-साइट जाँच पास नहीं कर सका।
web-auth-token-unknown = वह api टोकन मौजूद नहीं है, रद्द किया जा चुका है, या समाप्त हो चुका है।
web-auth-token-limit = इस होस्ट के पास पहले से api टोकन की अधिकतम संख्या है।
web-auth-totp-secret-invalid = वह ऑथेंटिकेटर सीक्रेट मान्य base32 नहीं है।
web-auth-store-unreadable = `{$path}` पढ़ा नहीं जा सका: {$reason}
web-auth-store-unwritable = `{$path}` को लिखने के लिए तैयार नहीं किया जा सका: {$reason}
web-auth-store-write-failed = `{$path}` लिखा नहीं जा सका: {$reason}
web-auth-store-malformed = `{$path}` मान्य detent क्रेडेंशियल फ़ाइल नहीं है: {$reason}
web-denied-scope = इस क्रेडेंशियल के पास `{$scope}` स्कोप नहीं है।

## detent-web — the api surface
web-request-malformed = अनुरोध की बॉडी उस आकार की नहीं है जिसकी यह एंडपॉइंट अपेक्षा करता है।
web-request-too-deep = अनुरोध की बॉडी बहुत गहराई तक नेस्टेड है।
web-api-unexpected-outcome = ऑपरेशन पूरा हुआ लेकिन उसका परिणाम प्रदर्शित नहीं किया जा सका।
