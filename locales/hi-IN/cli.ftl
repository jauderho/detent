# needs-review: machine-drafted Hindi translation; not yet checked by a native speaker.
## detent CLI — hi
## Source: locales/en-US/cli.ftl. Same ids, same placeables. Identifiers —
## module ids, paths, unit names, digests, enum wire names — are interpolated
## verbatim and are not translated.

## severity words, prefixed to every rendered diagnostic
cli-severity-error = त्रुटि
cli-severity-warning = चेतावनी
cli-severity-recommendation = टिप्पणी

## yes/no, used wherever a flag is rendered
cli-yes = हाँ
cli-no = नहीं

## progress notes, printed on stderr under --verbose
cli-note-settings = लोकेल {$locale}, स्टेट रूट {$state}, कॉन्फ़िग {$config}
cli-note-operation = {$module} के लिए {$operation} चल रहा है

## failures that stop a command before the operations layer sees it
cli-bad-stdin = stdin से मॉडल पढ़ा नहीं जा सका: {$reason}
cli-bad-json = stdin पर दिया गया मॉडल मान्य json नहीं है: {$reason}
cli-bad-hash = `{$value}` 64 हेक्स वर्णों वाला sha-256 डाइजेस्ट नहीं है।
cli-start-failed = विशेषाधिकार प्राप्त हेल्पर शुरू नहीं किया जा सका: {$reason}
cli-monitor-stop = विशेषाधिकार प्राप्त हेल्पर ठीक से बंद नहीं हुआ: {$reason}
cli-monitor-busy = कोई और detent मॉनिटर इस स्टेट रूट का स्वामी है; वेब UI से प्रयास करें या `detent serve` चलाएँ।
cli-monitor-lock-unavailable = {$path} में स्टेट लॉक नहीं लिया जा सकता, इसलिए यह कमांड कुछ भी नहीं बदल सकता; इसे ऐसे उपयोगकर्ता के रूप में चलाएँ जो उस डायरेक्टरी में लिख सके, या --state-root दें।
cli-commit-recovered = अपुष्ट कमिट {$commit} बहाल किया गया; {$failures} विफलताओं के साथ {$restored} लक्ष्य पुनर्स्थापित किए गए।
cli-commit-confirm-needs-serve = इस मॉड्यूल के लिए commit-confirm ज़रूरी है; वेब UI या `detent serve` का उपयोग करें ताकि पुष्टि की विंडो लागू बनी रहे।
cli-config-load-failed = {$path} का कॉन्फ़िगरेशन लोड नहीं किया जा सका: {$reason}
cli-no-command = कोई कमांड नहीं दी गई।

## self-test probe and self-update (PLAN §2.9)
cli-self-test = संस्करण {$version} फ़ीचर {$features}
cli-update-available = अपडेट उपलब्ध है: {$tag}, प्रकाशित {$published}
cli-update-security-available = सुरक्षा अपडेट उपलब्ध है: {$tag}, प्रकाशित {$published}
cli-update-none = कोई अपडेट उपलब्ध नहीं (वर्तमान {$current})
cli-update-held-young = {$tag}, {$current} से नया है लेकिन {$days} दिन से कम पुराना है; एज गेट इसे रोके हुए है
cli-update-held-rejected = {$tag}, {$current} से नया है लेकिन इस होस्ट पर रोलबैक किया गया था; इसे छोड़ दिया गया है
cli-verify-bundle-ok = {$file} का {$tag} के लिए सत्यापन हो गया है
cli-update-failed = अपडेट विफल: {$reason}
cli-update-installed = {$tag} इंस्टॉल हो गया; जिस बाइनरी को इसने बदला वह {$previous} पर रखी गई है
cli-update-not-restarted = सेवा रीस्टार्ट नहीं हुई, इसलिए नई बाइनरी अभी चल नहीं रही: {$reason}
cli-update-rolled-back = रोलबैक किया गया: {$reason}
cli-update-rollback-failed = अपडेट विफल रहा ({$reason}) और रोलबैक भी विफल रहा ({$error}); इस होस्ट पर ध्यान देने की ज़रूरत है

## config
cli-module-line = {$id}  {$name}
cli-no-model = यह मॉड्यूल अभी इस होस्ट पर कोई फ़ाइल प्रबंधित नहीं करता, इसलिए दिखाने के लिए कोई मॉडल नहीं है।
cli-valid = यह कॉन्फ़िगरेशन मान्य है।
cli-plan-no-change = {$module} पहले से वही है जो {$path} में है; कुछ नहीं बदलेगा।
cli-plan-service = इसे लागू करने से {$unit} प्रभावित होगा।
cli-plan-hash = फ़ाइल का हैश अब {$hash} है; इसे --expect-hash के रूप में दें ताकि बीच में हुआ संपादन अस्वीकार हो जाए।
cli-check-ran = अपस्ट्रीम वैलिडेटर {$program} चला; उत्तीर्ण: {$passed}। {$detail}
cli-check-skipped = अपस्ट्रीम वैलिडेटर {$program} नहीं चला। {$detail}
cli-applied = {$module} को {$path} में लिखा गया।
cli-applied-hash = इसका हैश {$prev} था और अब {$new} है; बैकअप रखा गया: {$backup}
cli-mounts-off = mounts: सक्रियण बंद है ([mounts] activate_new_entries); नई fstab प्रविष्टियाँ अगले बूट या माउंट पर प्रभावी होती हैं।
cli-mounts-error = mounts: कोई माउंट यूनिट शुरू नहीं हुई: {$reason}
cli-mounts-none = mounts: माउंट करने के लिए कोई नई fstab प्रविष्टि नहीं है।
cli-mounts-unit = माउंट {$mountpoint} ({$unit}): {$state}
cli-mounts-unit-detail = माउंट {$mountpoint} ({$unit}): {$state}: {$detail}
cli-commit-armed = कमिट {$id} की पुष्टि {$seconds} सेकंड के भीतर, यानी {$deadline} तक, करनी होगी, वरना उसे रोलबैक कर दिया जाएगा।
cli-commit-confirmed = कमिट {$id} की पुष्टि हो गई है और उसे रोलबैक नहीं किया जाएगा।
cli-commit-rolled-back = कमिट {$id} रोलबैक किया गया; {$targets} लक्ष्य वापस रखे गए।

## backups
cli-no-backups = इस मॉड्यूल के लिए अभी तक कोई बैकअप नहीं रखा गया है।
cli-backup-line = {$id}  {$name}  {$bytes} बाइट  {$digest}
cli-restored = लक्ष्य {$target} वापस रखा गया और अब उसका हैश {$hash} है।

## services
cli-service-status = {$unit} {$state} है; बूट पर शुरू होता है: {$enabled}
cli-serviced = {$unit} से {$action} करने को कहा गया; अभी चल रहा है: {$active}

## host
cli-host-profile = {$hostname}: {$os}, init {$init}, {$ram} mib रैम
cli-host-service-version = इंस्टॉल किया गया {$service} संस्करण {$version} है
cli-host-backends = नेटवर्क बैकएंड {$network}, रिज़ॉल्वर बैकएंड {$resolver}, डिस्ट्रो {$distro} {$version}
cli-host-note = पहचान टिप्पणी: {$note}

## audit
cli-no-audit = ऑडिट लॉग में कोई मेल खाता रिकॉर्ड नहीं है।
cli-audit-line = {$ts}  {$who}  {$op}  {$module}  {$result}  {$error}
cli-audit-verified = ऑडिट चेन रिकॉर्ड {$sequence} तक अक्षुण्ण है; हेड डाइजेस्ट {$hash}
cli-audit-broken = ऑडिट चेन का सत्यापन नहीं हो सका: {$reason}

## --dryrun
cli-dryrun-apply = ड्राई रन: {$module} के लिए {$path} में यही लिखा जाएगा।
cli-dryrun-operation = ड्राई रन: {$module} के लिए {$operation} चलेगा।
cli-dryrun-nothing = ड्राई रन: कुछ नहीं बदला गया।
cli-dryrun-serve = ड्राई रन: मॉनिटर और वर्कर {$modules} मॉड्यूल और {$targets} लक्ष्यों के साथ, {$state} को रूट मानकर शुरू होंगे।
cli-dryrun-serve-mounts = ड्राई रन: mounts apply के बाद रनर नई fstab प्रविष्टियों की माउंट यूनिट शुरू करेगा (mounts.activate_new_entries = true)।
cli-dryrun-cert-renew = ड्राई रन: {$address} पर सर्वर से ({$name} के रूप में) अभी अपना प्रमाणपत्र नवीनीकृत करने को कहा जाएगा; कुछ भेजा नहीं गया।

## serve
cli-serve-monitor = वर्कर pid {$pid} के रूप में शुरू हुआ; विशेषाधिकार हटाए गए: {$dropped}
cli-serve-worker = वर्कर चल रहा है; इसका http सर्वर चरण 4 में आएगा। हैंडशेक: {$greeted}
cli-serve-failed = मॉनिटर और वर्कर शुरू नहीं किए जा सके: {$reason}
cli-serve-stopped = जोड़ी अप्रत्याशित रूप से रुक गई: {$reason} {$status}
cli-serve-privileged-port = पोर्ट {$port} के लिए cap_net_bind_service या मॉनिटर द्वारा दिया गया सॉकेट चाहिए, जिनमें से कोई भी यह बिल्ड समर्थित नहीं करता; 1024 या उससे ऊँचा पोर्ट उपयोग करें, या आगे रिवर्स प्रॉक्सी लगाएँ।
cli-serve-privilege-mode = कॉन्फ़िगर किया गया विशेषाधिकार मोड इस प्रक्रिया से मेल नहीं खाता, इसलिए सेवा शुरू नहीं हुई: {$reason}
cli-serve-acme-unsupported = इस बिल्ड में कोई dns-01 प्रदाता नहीं है (फ़ीचर acme-dns-providers), इसलिए यह acme प्रमाणपत्र प्राप्त नहीं कर सकता; {$path} में tls.bootstrap को "self-signed" पर सेट करें।
cli-serve-acme-setting-missing = tls.bootstrap "acme" है, लेकिन {$path} में {$setting} सेट नहीं है।
cli-serve-acme-path-outside = {$setting} ({$value}) स्टेट रूट {$root} के अंतर्गत नहीं है: सीमित प्रक्रियाएँ केवल वहीं लिखती हैं।
cli-serve-acme-credentials-dir = acme क्रेडेंशियल डायरेक्टरी {$path} तैयार नहीं की जा सकी: {$reason}
cli-serve-secrets-failed = सीक्रेट फ़ाइल {$path} अस्वीकार कर दी गई: {$reason}
cli-serve-acme-secret-missing = acme.provider सेट है, लेकिन {$path} की [acme] तालिका में dns_provider सीक्रेट नहीं है।
cli-serve-acme-provider-invalid = acme.provider में दिया गया dns-01 प्रदाता उपयोग नहीं किया जा सकता: {$reason}
cli-serve-acme-providers-not-built = इस बिल्ड में कोई dns-01 प्रदाता नहीं है (फ़ीचर acme-dns-providers); {$path} से [acme.provider] हटाएँ।
cli-serve-handshake-failed = वर्कर मॉनिटर के साथ अपना हैंडशेक पूरा नहीं कर सका।
cli-serve-auth-failed = खाता, टोकन और सत्र स्टोर खोला नहीं जा सका: {$reason}
cli-serve-tls-failed = tls प्रमाणपत्र तैयार नहीं किया जा सका: {$reason}
cli-serve-cert-fingerprint = tls बूटस्ट्रैप प्रमाणपत्र फ़िंगरप्रिंट (sha-256): {$fingerprint}
cli-serve-web-failed = वेब सर्वर शुरू नहीं हो सका: {$reason}
cli-serve-web-stopped = वेब सर्वर ठीक से बंद नहीं हुआ: {$reason}
cli-serve-listening = {$addr} पर सुन रहा है
cli-serve-confinement-degraded = कन्फ़ाइनमेंट कमज़ोर हुआ: {$detail}
cli-mcp-missing-token = {$var} सेट नहीं है; `detent token create` से एक बनाएँ और mcp सर्वर शुरू करने से पहले उसे एक्सपोर्ट करें।
cli-mcp-serve-failed = mcp सर्वर शुरू नहीं हो सका: {$reason}
cli-mcp-listening = mcp {$transport} परोस रहा है
cli-mcp-http-needs-privsep = mcp http ट्रांसपोर्ट root के रूप में या capabilities के साथ नहीं चल सकता: नेटवर्क पार्सर root जैसी शक्ति से चलेगा; बिना capabilities के गैर-root उपयोगकर्ता के रूप में चलाएँ या stdio ट्रांसपोर्ट का उपयोग करें।
cli-mcp-bind-not-loopback = mcp http बाइंड लूपबैक (127.0.0.1 या ::1) होना चाहिए; बेयरर तार पर सादे पाठ में जाता है।
cli-dryrun-mcp = ड्राई रन: mcp {$addr} पर स्कोप {$scope} के साथ {$transport} परोसेगा।

## setup, user, token
cli-setup-exists = `{$name}` नाम का उपयोगकर्ता इस होस्ट पर पहले से मौजूद है; उसे ओवरराइट करने के लिए --force दें।
cli-setup-created = व्यवस्थापक खाता `{$name}` बना दिया गया।
cli-user-created = खाता `{$name}` बना दिया गया।
cli-user-passwd = `{$name}` का पासवर्ड बदल दिया गया।
cli-user-removed = खाता `{$name}` हटा दिया गया।
cli-totp-uri = इसे अपने ऑथेंटिकेटर ऐप में जोड़ें: {$uri}
cli-totp-secret = या यह कुंजी उसमें टाइप करें: {$secret}
cli-totp-code-prompt = आपके ऑथेंटिकेटर से कोड:
cli-totp-code-empty = कोड खाली नहीं हो सकता।
cli-totp-code-wrong = वह कोड मान्य नहीं है, इसलिए दूसरा कारक चालू नहीं किया गया।
cli-user-totp-enabled = `{$name}` के लिए दूसरा कारक चालू कर दिया गया।
cli-totp-disable-prompt = `{$name}` के लिए दूसरा कारक बंद करें? [y/N]
cli-totp-disable-cancelled = `{$name}` के लिए दूसरा कारक चालू रखा गया।
cli-user-totp-disabled = `{$name}` के लिए दूसरा कारक बंद कर दिया गया।
cli-token-created = टोकन {$id} ({$label}) बना दिया गया; यह दोबारा नहीं दिखाया जाएगा: {$token}
cli-token-revoked = टोकन {$id} रद्द कर दिया गया।
cli-token-no-tokens = कोई टोकन जारी नहीं किया गया है।
cli-token-line = {$id}  {$label}  {$scopes}  {$created}  {$expires}
cli-credential-failed = अनुरोध पूरा नहीं किया जा सका: {$reason}
cli-audit-failed = बदलाव कर दिया गया, लेकिन उसका ऑडिट रिकॉर्ड लिखा नहीं जा सका: {$reason}
cli-state-command-as-root = detent {$command} को root के रूप में नहीं चलाना चाहिए: यह जो फ़ाइलें लिखेगा वे root की होंगी और सेवा उन्हें पढ़ नहीं सकेगी। इसे सेवा खाते के रूप में चलाएँ: sudo -u {$account} detent {$command}

## cert status
cli-cert-source = स्रोत: {$source}
cli-cert-fingerprint = फ़िंगरप्रिंट (sha-256): {$fingerprint}
cli-cert-not-after = समाप्ति: {$not_after}
cli-cert-not-after-unknown = समाप्ति: अज्ञात (प्रमाणपत्र पार्स नहीं हुआ)।
cli-cert-lifetime = उपयोग की गई अवधि: {$percent} (चेतावनी: {$warning})।
cli-cert-lifetime-no-warning = उपयोग की गई अवधि: {$percent} (कोई चेतावनी नहीं)।
cli-cert-lifetime-unknown = उपयोग की गई अवधि: अज्ञात (प्रमाणपत्र पार्स नहीं हुआ)।
cli-cert-missing = {$path} में कोई प्रमाणपत्र संग्रहीत नहीं है; सर्वर को एक बार शुरू करें ताकि वह एक लिख दे।
cli-cert-unreadable = {$path} में प्रमाणपत्र पढ़ा नहीं जा सका: {$reason}

## cert renew
cli-cert-renew-requested = नवीनीकरण का अनुरोध किया गया: सर्वर ने अपने ACME क्लाइंट से अभी नवीनीकरण करने को कहा। परिणाम `detent cert status` से जाँचें।
cli-cert-renew-token-refused = टोकन अस्वीकार कर दिया गया (HTTP {$status}); इसके लिए write स्कोप चाहिए: `detent token create <name> --write`।
cli-cert-renew-not-acme = सर्वर कोई ACME प्रक्रिया नहीं चलाता (`tls.bootstrap` `acme` नहीं है), इसलिए नवीनीकरण के लिए कुछ नहीं है।
cli-cert-renew-server-error = सर्वर ने HTTP {$status} के साथ उत्तर दिया: {$message_id}
cli-cert-renew-server-error-bare = सर्वर ने HTTP {$status} के साथ उत्तर दिया।
cli-cert-renew-unreachable = {$address} पर सर्वर से संपर्क नहीं हो सका: {$reason}
cli-cert-renew-no-token = कोई API टोकन नहीं: --token-file <path> दें या {$var} सेट करें। write टोकन `detent token create <name> --write` से बनाएँ।
cli-cert-renew-bad-token = {$source} से मिला टोकन अस्वीकार कर दिया गया: {$reason}
cli-cert-renew-ca-unreadable = CA फ़ाइल {$path} पढ़ी नहीं जा सकी: {$reason}

## password entry (setup, user add, user passwd)
cli-password-prompt = पासवर्ड:
cli-password-confirm = पासवर्ड की पुष्टि करें:
cli-password-mismatch = पासवर्ड मेल नहीं खाए।
cli-password-empty = पासवर्ड खाली नहीं हो सकता।

## doctor
cli-status-ok = ठीक
cli-status-warn = चेतावनी
cli-status-fail = विफल
cli-doctor-modules = इस बिल्ड में कंपाइल किए गए मॉड्यूल: {$detail}
cli-doctor-state-root = स्टेट डायरेक्टरी {$detail}
cli-doctor-config = कॉन्फ़िगरेशन फ़ाइल {$detail}
cli-doctor-privsep = विशेषाधिकार पृथक्करण एक काम करने वाली जोड़ी फ़ोर्क कर सकता है: {$detail}
cli-doctor-landlock = landlock: {$detail}
cli-doctor-seccomp = seccomp: {$detail}
cli-doctor-confinement = सैंडबॉक्स कन्फ़ाइनमेंट: {$detail}
cli-doctor-serve-confinement = पिछले serve स्टार्ट पर कन्फ़ाइनमेंट: {$detail}
cli-doctor-mounts = fstab apply के बाद माउंट सक्रियण: {$detail}
cli-doctor-privilege-mode = विशेषाधिकार मोड: {$detail}
cli-doctor-service-account = सेवा खाता: {$detail}
cli-doctor-state-owner = स्टेट डायरेक्टरी का स्वामी: {$detail}
cli-doctor-backups-dir = बैकअप डायरेक्टरी: {$detail}
cli-doctor-polkit-rule = polkit नियम: {$detail}
cli-doctor-polkit-daemon = polkit डेमन: {$detail}
cli-doctor-unit-capabilities = सेवा यूनिट की पहचान और capabilities: {$detail}
