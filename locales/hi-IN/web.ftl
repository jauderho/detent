# needs-review: machine-drafted Hindi translation; not yet checked by a native speaker.
## detent web admin UI — hi
## Source: locales/en-US/web.ftl. Same ids, same placeables.

## Status bar
status-brand = detent
status-online = सिस्टम ऑनलाइन
status-clock-label = utc
status-mode-label = मोड
theme-toggle-aria = लाइट और डार्क मोड बदलें
theme-toggle-title = लाइट / डार्क बदलें

## catfu component layer
## Chrome the shared components render themselves. Content strings (field
## captions, table headers, banner copy) are supplied by the calling page.
component-countdown-remaining = शेष समय
component-field-info = अधिक जानकारी
component-modal-close = बंद करें
component-switch-off = बंद
component-switch-on = चालू
component-table-empty = कोई रिकॉर्ड नहीं

## API failures
## docs/API.md: every failure is `{ code, message_id }`, and `message_id` is a
## Fluent id. src/api/messages.ts resolves it here; an id this build does not
## know falls back to `api-error-unknown`, so an id is never rendered raw.
##
## The first three are the console's own — a failure that never reached a
## server has no `message_id` to resolve. The rest mirror the ids the server
## sends, argument-free: locales/en-US/core.ftl interpolates `{$path}`,
## `{$reason}` and friends, and the API deliberately sends none of them.
api-error-network = कंसोल इस होस्ट तक नहीं पहुँच सका।
api-error-malformed = इस होस्ट ने ऐसा उत्तर भेजा जिसे कंसोल पढ़ नहीं सका।
api-error-unknown = इस होस्ट ने ऐसी विफलता बताई जिसका कंसोल के पास कोई विवरण नहीं है।
core-edit-index-out-of-range = आंतरिक त्रुटि: किसी संपादन ने फ़ाइल के बाहर की पंक्ति को संबोधित किया।
core-edit-line-break = मान में नई पंक्ति या null बाइट नहीं हो सकती।
core-edit-unsupported = यह संपादन फ़ाइल के प्रारूप में व्यक्त नहीं किया जा सकता।
core-model-shape = दिया गया कॉन्फ़िगरेशन अपेक्षित आकार का नहीं है।
core-model-unrepresentable = इस फ़ाइल में कुछ ऐसा है जिसे संपादक प्रस्तुत नहीं कर सकता।
core-parse-malformed = यह फ़ाइल उस प्रारूप से मेल नहीं खाती जिसकी उसका मॉड्यूल अपेक्षा करता है।
ops-audit-failed = ऑडिट लॉग पढ़ा नहीं जा सका।
ops-audit-unavailable = ऑडिट लॉग लिखा नहीं जा सका, इसलिए ऑपरेशन अस्वीकार कर दिया गया।
ops-denied = आपको ऐसा करने की अनुमति नहीं है।
ops-hash-conflict = पढ़े जाने के बाद फ़ाइल डिस्क पर बदल गई; इसे फिर से पढ़ें और दोबारा प्रयास करें।
ops-check-failed = बाहरी वैलिडेटर ने उम्मीदवार को अस्वीकार कर दिया।
ops-invalid-model = वह कॉन्फ़िगरेशन मान्य नहीं है।
ops-no-service = यह मॉड्यूल इस होस्ट पर कोई सेवा नियंत्रित नहीं करता, इसलिए उसे रीस्टार्ट नहीं किया जा सकता।
ops-no-target = यह मॉड्यूल इस होस्ट पर कोई फ़ाइल प्रबंधित नहीं करता।
ops-privsep-failed = विशेषाधिकार प्राप्त हेल्पर ने अनुरोध अस्वीकार कर दिया या पूरा नहीं कर सका।
ops-service-failed = सेवा की कार्रवाई पूरी नहीं हुई।
ops-unknown-module = इस बिल्ड में उस नाम का कोई मॉड्यूल नहीं है।
ops-unsupported = वह इस बिल्ड में समर्थित नहीं है।
ops-commit-pending = एक और commit-confirm विंडो पहले से लंबित है।
ops-update-running = अपडेट पहले से चल रहा है; उसके पूरा होने तक प्रतीक्षा करें, फिर चल रहा संस्करण जाँचें।
ops-update-tag-invalid = यह रिलीज़ संस्करण नहीं है; यह v1.2.3 जैसा दिखना चाहिए।
ops-update-not-newer = वह रिलीज़ चल रहे संस्करण से नई नहीं है; कुछ शुरू नहीं किया गया।
ops-no-backup = commit-confirm के लिए रखा हुआ बैकअप चाहिए; कुछ भी नहीं बदला गया।
ops-arm-failed-restored = commit-confirm सक्रिय नहीं किया जा सका, इसलिए बदलाव पूर्ववत कर दिया गया; पिछली सामग्री वापस आ गई है।
ops-arm-failed-unrestored = commit-confirm सक्रिय नहीं किया जा सका और बदलाव पूर्ववत नहीं किया जा सका; नई सामग्री अब भी डिस्क पर है। अभी पिछला बैकअप पुनर्स्थापित करें।
ops-target-missing = प्रबंधित फ़ाइल मौजूद नहीं है; इसे बनाएँ (इसका पैकेज इंस्टॉल करें या हाथ से बनाएँ), फिर दोबारा प्रयास करें।
web-api-unexpected-outcome = ऑपरेशन पूरा हुआ लेकिन उसका परिणाम प्रदर्शित नहीं किया जा सका।
web-auth-ambiguous-credentials = या तो सत्र कुकी भेजें या बेयरर टोकन, दोनों नहीं।
web-auth-argon2-params = कॉन्फ़िगर किए गए argon2 पैरामीटर उपयोग योग्य नहीं हैं।
web-auth-busy = बहुत अधिक साइन-इन चल रहे हैं; थोड़ी देर प्रतीक्षा करें और फिर प्रयास करें।
web-auth-csrf-rejected = यह अनुरोध अपनी क्रॉस-साइट जाँच पास नहीं कर सका; पेज रीलोड करें और फिर प्रयास करें।
web-auth-entropy-unavailable = सिस्टम का रैंडम नंबर जनरेटर विफल रहा, इसलिए कोई क्रेडेंशियल जारी नहीं किया जा सका।
web-auth-hash-failed = पासवर्ड का हैश नहीं बनाया जा सका।
web-auth-invalid-credentials = उपयोगकर्ता नाम, पासवर्ड या कोड सही नहीं था।
web-auth-password-change-required = कुछ भी और करने से पहले अपना पासवर्ड बदलें।
web-auth-password-too-long = पासवर्ड में अधिकतम 128 वर्ण हो सकते हैं।
web-auth-password-too-short = पासवर्ड में कम से कम 12 वर्ण होने चाहिए।
web-auth-password-unchanged = नया पासवर्ड मौजूदा पासवर्ड से अलग होना चाहिए।
web-auth-rate-limited = बहुत अधिक प्रयास; थोड़ी देर प्रतीक्षा करें और फिर प्रयास करें।
web-auth-session-limit = बहुत अधिक सत्र खुले हैं; किसी के समाप्त होने की प्रतीक्षा करें और फिर साइन इन करें।
web-auth-store-malformed = इस होस्ट की एक क्रेडेंशियल फ़ाइल मान्य नहीं है।
web-auth-store-unreadable = इस होस्ट की एक क्रेडेंशियल फ़ाइल पढ़ी नहीं जा सकी।
web-auth-store-unwritable = इस होस्ट की एक क्रेडेंशियल फ़ाइल को लिखने के लिए तैयार नहीं किया जा सका।
web-auth-store-write-failed = इस होस्ट की एक क्रेडेंशियल फ़ाइल लिखी नहीं जा सकी।
web-auth-token-limit = इस होस्ट के पास पहले से api टोकन की अधिकतम संख्या है।
web-auth-token-unknown = वह api टोकन मौजूद नहीं है, रद्द किया जा चुका है, या समाप्त हो चुका है।
web-auth-totp-secret-invalid = वह ऑथेंटिकेटर सीक्रेट मान्य base32 नहीं है।
web-auth-unauthenticated = ऐसा करने के लिए साइन इन करें।
web-auth-user-exists = उस नाम का उपयोगकर्ता पहले से मौजूद है।
web-auth-user-name-invalid = वह उपयोगकर्ता नाम उपयोग योग्य नहीं है; `a-z`, `0-9`, `.`, `_` या `-` के 1 से 32 वर्ण उपयोग करें, जो किसी अक्षर या अंक से शुरू हों।
web-auth-user-unknown = उस नाम का कोई उपयोगकर्ता नहीं है।
web-cert-renew-not-acme = नवीनीकरण के लिए detent.toml में `tls.bootstrap = "acme"` चाहिए।
web-cert-renew-unavailable = acme क्लाइंट को नवीनीकरण का अनुरोध नहीं मिला; बाद में फिर प्रयास करें।
web-denied-scope = इस क्रेडेंशियल के पास वह स्कोप नहीं है जो उस कार्रवाई के लिए चाहिए।
web-engine-stopped = ऑपरेशन इंजन अब नहीं चल रहा; सेवा लौटने पर फिर प्रयास करें।
web-update-not-checked = इस होस्ट पर अभी तक कोई अपडेट जाँच नहीं चली है; root के रूप में `detent update --check` चलाएँ।
web-request-malformed = अनुरोध की बॉडी उस आकार की नहीं है जिसकी यह एंडपॉइंट अपेक्षा करता है।
web-request-too-deep = अनुरोध की बॉडी बहुत गहराई तक नेस्टेड है।

## Sign in
login-title = साइन इन
login-panel-label = सत्र
login-username-label = उपयोगकर्ता नाम
login-password-label = पासवर्ड
login-totp-label = ऑथेंटिकेटर कोड
login-totp-description = इस खाते के लिए पंजीकृत ऑथेंटिकेटर से छह अंक।
login-totp-reveal = ऑथेंटिकेटर कोड का उपयोग करें
login-submit = साइन इन
login-submitting = साइन इन हो रहा है
login-retry-after = बहुत अधिक प्रयास; {$seconds} सेकंड प्रतीक्षा करें और फिर प्रयास करें।

## Change password
password-change-title = अपना पासवर्ड बदलें
password-change-panel-label = पासवर्ड
password-change-intro = इस खाते को कुछ भी और करने से पहले नया पासवर्ड सेट करना होगा।
password-change-current-label = वर्तमान पासवर्ड
password-change-new-label = नया पासवर्ड
password-change-new-description = 12 से 128 वर्ण; कोई भी वर्ण मान्य है।
password-change-confirm-label = नए पासवर्ड की पुष्टि करें
password-change-mismatch = दोनों नए पासवर्ड एक जैसे नहीं हैं।
password-change-submit = पासवर्ड बदलें
password-change-submitting = पासवर्ड बदला जा रहा है

## Session and scope
auth-checking = इस सत्र की जाँच हो रही है
auth-sign-out = साइन आउट
scope-gate-read-only = इस सत्र के पास केवल पढ़ने की पहुँच है; यह इस होस्ट पर कुछ भी नहीं बदल सकता।
scope-gate-signed-out = इस होस्ट पर कुछ भी बदलने के लिए साइन इन करें।

## Navigation
nav-label = अनुभाग
nav-dashboard = डैशबोर्ड
nav-modules = मॉड्यूल
nav-services = सेवाएँ
nav-backups = बैकअप
nav-audit = ऑडिट
nav-certificates = प्रमाणपत्र
nav-settings = सेटिंग

## Routed pages
## Certificates and settings are still named placeholders: neither has an API
## to drive. Certificates waits on Phase 6 (ACME); settings waits on the user
## and token endpoints.
page-placeholder-body = यह अनुभाग अभी बना नहीं है।
page-dashboard-title = डैशबोर्ड
page-modules-title = मॉड्यूल
page-module-detail-title = मॉड्यूल {$module}
page-services-title = सेवाएँ
page-backups-title = बैकअप
page-audit-title = ऑडिट लॉग
page-certificates-title = प्रमाणपत्र
page-settings-title = सेटिंग
page-not-found-title = ऐसा कोई पेज नहीं
page-not-found-body = वह पता इस कंसोल में किसी चीज़ का नाम नहीं है।
page-not-found-home = डैशबोर्ड पर जाएँ

## Pending commit
pending-commit-message = एक कॉन्फ़िगरेशन बदलाव पुष्टि की प्रतीक्षा में है; यह विंडो बंद होने पर वह अपने आप रोलबैक हो जाता है।
pending-commit-countdown-label = पुष्टि के लिए शेष समय
pending-commit-confirm = बदलाव की पुष्टि करें
pending-commit-confirming = पुष्टि हो रही है…

## Shared page states
## Every section is a query away from its data, so loading, failure and "this
## host has none of these" are shared rather than re-worded per page.
state-loading = लोड हो रहा है
state-unknown = अज्ञात
value-no = नहीं
value-yes = हाँ

## Dashboard
dashboard-host-panel = होस्ट
dashboard-host-hostname = होस्टनाम
dashboard-host-os = ऑपरेटिंग सिस्टम
dashboard-host-init = init सिस्टम
dashboard-host-distro = डिस्ट्रीब्यूशन
dashboard-host-ram = मेमोरी
dashboard-host-network-backend = नेटवर्क बैकएंड
dashboard-host-resolver-backend = रिज़ॉल्वर बैकएंड
dashboard-host-notes = पहचान टिप्पणियाँ
dashboard-cert-panel = प्रमाणपत्र
dashboard-cert-fingerprint = फ़िंगरप्रिंट
dashboard-cert-expires = समाप्ति
dashboard-cert-lifetime-used = उपयोग की गई अवधि
dashboard-cert-expired = समाप्त हो चुका है; इस प्रमाणपत्र को बदलें।
dashboard-cert-expiring-soon = 30 दिनों के भीतर समाप्त हो रहा है; नवीनीकरण की योजना बनाएँ।
dashboard-cert-half = प्रमाणपत्र की आधी अवधि बीत चुकी है; नवीनीकरण निर्धारित है।
dashboard-cert-quarter = प्रमाणपत्र की तीन-चौथाई अवधि बीत चुकी है; जल्द नवीनीकरण करें।
cert-renew-panel = नवीनीकरण
cert-renew-now = अभी नवीनीकरण करें
cert-renew-requested = नवीनीकरण का अनुरोध किया गया। CA द्वारा जारी करते ही नया प्रमाणपत्र इंस्टॉल हो जाएगा।
dashboard-modules-panel = मॉड्यूल
dashboard-modules-count = {$count ->
    [one] {$count} मॉड्यूल इस बिल्ड में कंपाइल किया गया है।
   *[other] {$count} मॉड्यूल इस बिल्ड में कंपाइल किए गए हैं।
}
dashboard-audit-panel = हाल की गतिविधि
dashboard-view-all = सभी देखें
dashboard-update-panel = अपडेट
dashboard-update-current = चल रहा संस्करण
dashboard-update-published = प्रकाशित
dashboard-update-up-to-date = इस बिल्ड के लिए कोई नई रिलीज़ उपलब्ध नहीं है।
dashboard-update-available = इस बिल्ड के लिए रिलीज़ {$tag} उपलब्ध है।
dashboard-update-security = यह रिलीज़ सुरक्षा अपडेट के रूप में चिह्नित है; यह एज गेट को लाँघ जाती है।
dashboard-update-install = {$tag} इंस्टॉल करें
dashboard-update-confirm-title = यह अपडेट इंस्टॉल करें?
dashboard-update-confirm-body = इससे {$tag} का इंस्टॉल बैकग्राउंड में शुरू होता है। इंस्टॉल हो जाने पर detent सेवा रीस्टार्ट होती है और पेज का कनेक्शन टूटकर फिर जुड़ सकता है; यदि रीस्टार्ट हुई सेवा स्वस्थ नहीं होती, तो अपडेट रोलबैक हो जाता है।
dashboard-update-confirm-action = इंस्टॉल करें
dashboard-update-confirm-cancel = रद्द करें
dashboard-update-started = {$version} का अपडेट बैकग्राउंड में शुरू हो गया। इंस्टॉल होने पर सेवा रीस्टार्ट होती है और स्वस्थ न होने पर रोलबैक हो जाती है; परिणाम चल रहे संस्करण में दिखता है।

## Modules
modules-panel-label = इंस्टॉल किए गए मॉड्यूल
modules-col-module = मॉड्यूल
modules-col-targets = फ़ाइलें
modules-col-services = सेवाएँ
modules-col-commit-confirm = commit-confirm
modules-commit-confirm-required = आवश्यक
modules-commit-confirm-not-required = आवश्यक नहीं
modules-empty = इस बिल्ड में कोई मॉड्यूल कंपाइल नहीं किया गया है।
modules-none = कोई नहीं

## One module
module-about-panel = मॉड्यूल
module-configuration-panel = कॉन्फ़िगरेशन
module-upstream-label = अपस्ट्रीम को ट्रैक करता है
module-targets-label = फ़ाइलें
module-services-label = सेवाएँ
module-current-hash-label = डिस्क पर डाइजेस्ट
module-security-notes-label = सुरक्षा टिप्पणियाँ
module-model-missing = इस मॉड्यूल की फ़ाइल इस होस्ट पर अभी मौजूद नहीं है। नीचे का फ़ॉर्म मॉड्यूल के अपने डिफ़ॉल्ट से शुरू होता है, और लागू करने पर फ़ाइल बन जाती है।
module-action-validate = सत्यापित करें
module-action-plan = योजना
module-action-apply = लागू करें
module-action-discard = संपादन हटाएँ
module-busy = काम चल रहा है
module-validate-clean = यह कॉन्फ़िगरेशन इस होस्ट की हर जाँच में उत्तीर्ण हुआ।
module-plan-title = नियोजित बदलाव
module-plan-no-change = यह कॉन्फ़िगरेशन वही है जो डिस्क पर पहले से है; लागू करने के लिए कुछ नहीं है।
module-plan-diff-label = diff
module-plan-checks-label = अपस्ट्रीम जाँच
module-plan-check-passed = उत्तीर्ण
module-plan-check-failed = विफल
module-plan-check-exit = exit {$code}
module-plan-services-label = इससे प्रभावित होने वाली सेवाएँ
module-plan-apply = यह बदलाव लागू करें
module-apply-title = यह बदलाव लागू करें?
module-apply-body = इससे इस होस्ट पर {$path} लिखा जाता है। पहले वर्तमान सामग्री का बैकअप लिया जाता है।
module-apply-commit-confirm = यह मॉड्यूल व्यवस्थापक को बाहर कर सकता है, इसलिए यह बदलाव commit-confirm विंडो सक्रिय करता है: यदि आप समय-सीमा से पहले पुष्टि नहीं करते, तो वह अपने आप रोलबैक हो जाता है।
module-apply-service-label = इसके बाद
module-apply-service-none = सेवा को जैसा है वैसा छोड़ें
module-apply-cancel = रद्द करें
module-applied = बदलाव {$path} में लिख दिया गया।
module-applied-created = {$path} मौजूद नहीं था और बना दिया गया।
module-mounts-off = नई fstab प्रविष्टियाँ माउंट नहीं की गईं ([mounts] activate_new_entries बंद है); वे अगले बूट या माउंट पर प्रभावी होती हैं।
module-mounts-error = कोई माउंट यूनिट शुरू नहीं हुई: {$reason}
module-mounts-none = माउंट करने के लिए कोई नई fstab प्रविष्टि नहीं है।
module-mounts-units = नई fstab प्रविष्टियों की माउंट यूनिट:
module-mount-state-mounted = माउंट हुआ
module-mount-state-already-mounted = पहले से माउंट है
module-mount-state-pending = अभी माउंट हो रहा है
module-mount-state-failed = विफल
module-mount-state-protected = अस्वीकृत: संरक्षित पथ
module-mount-state-stopped = अनमाउंट हुआ
module-cancel = रद्द करें

## Services
services-panel-label = सेवाएँ
services-col-module = मॉड्यूल
services-col-unit = यूनिट
services-col-state = स्थिति
services-col-enabled = बूट पर
services-col-since = से
services-col-actions = कार्रवाइयाँ
services-state-active = सक्रिय
services-state-inactive = निष्क्रिय
services-state-failed = विफल
services-state-activating = शुरू हो रहा है
services-state-deactivating = रुक रहा है
services-state-unknown = अज्ञात
services-action-restart = रीस्टार्ट
services-action-reload = रीलोड
services-action-start = शुरू करें
services-action-stop = रोकें
services-acted = {$unit}: {$detail}
services-empty = इस बिल्ड का कोई मॉड्यूल इस होस्ट पर कोई सेवा नियंत्रित नहीं करता।
services-confirm-title = {$unit}: {$action}?
services-confirm-body = यह चल रही सेवा पर तुरंत कार्रवाई करता है।
services-confirm-cancel = रद्द करें

## Backups
backups-col-name = बैकअप
backups-col-created = लिया गया
backups-col-size = आकार
backups-col-digest = डाइजेस्ट
backups-col-actions = कार्रवाइयाँ
backups-action-restore = पुनर्स्थापित करें
backups-confirm-title = यह बैकअप पुनर्स्थापित करें?
backups-confirm-body = इससे {$target} रखी हुई प्रति से बदल जाता है। पहले वर्तमान सामग्री का बैकअप लिया जाता है।
backups-confirm-cancel = रद्द करें
backups-restored = बैकअप पुनर्स्थापित कर दिया गया।
backups-empty = इस मॉड्यूल का अभी तक कुछ भी बैकअप नहीं लिया गया है।
backups-module-panel = {$module} बैकअप

## Audit log
audit-panel-label = ऑडिट लॉग
audit-col-when = कब
audit-col-who = कॉलर
audit-col-how = क्रेडेंशियल
audit-col-op = ऑपरेशन
audit-col-module = मॉड्यूल
audit-col-result = परिणाम
audit-filter-module-label = मॉड्यूल
audit-filter-who-label = कॉलर
audit-filter-limit-label = पंक्तियाँ
audit-filter-apply = फ़िल्टर करें
audit-filter-clear = साफ़ करें
audit-empty = इस होस्ट पर अभी तक कुछ भी दर्ज नहीं किया गया है।
audit-result-ok = ठीक
audit-result-denied = अस्वीकृत
audit-result-error = विफल
audit-identity-local-user = स्थानीय उपयोगकर्ता
audit-identity-session = सत्र
audit-identity-token = api टोकन
audit-op-list-modules = मॉड्यूल सूचीबद्ध करें
audit-op-get-module = मॉड्यूल पढ़ें
audit-op-validate = सत्यापित करें
audit-op-plan = योजना
audit-op-apply = लागू करें
audit-op-confirm-commit = कमिट की पुष्टि करें
audit-op-rollback-commit = कमिट रोलबैक करें
audit-op-list-backups = बैकअप सूचीबद्ध करें
audit-op-restore = बैकअप पुनर्स्थापित करें
audit-op-service-status = सेवा की स्थिति पढ़ें
audit-op-service-action = सेवा पर कार्रवाई करें
audit-op-host-profile = होस्ट प्रोफ़ाइल पढ़ें
audit-op-audit-query = ऑडिट लॉग पढ़ें
audit-op-cert-status = प्रमाणपत्र की स्थिति पढ़ें
audit-op-update-status = अपडेट की स्थिति पढ़ें
audit-op-cert-renew = प्रमाणपत्र का नवीनीकरण करें
audit-op-update-apply = अपडेट इंस्टॉल करें
## Schema-driven module forms
## Chrome the form engine (web/src/forms) renders around a module's schema.
## Field captions come from the schema's own property names, and a field's
## tooltip and recommendation are Fluent ids in the *module's* locale file, not
## here — a missing one degrades to no tooltip and is never rendered raw.
forms-advanced-toggle = उन्नत
forms-badge-security-high = उच्च सुरक्षा प्रभाव
forms-badge-deprecated = {$version} में अप्रचलित
forms-diagnostic-at-field = {$field}: {$message}
forms-diagnostic-unknown = इस होस्ट ने ऐसा जाँच परिणाम बताया जिसका इस बिल्ड के पास कोई विवरण नहीं है ({$id})।
forms-item-add-caption = जोड़ें
forms-item-move-down-caption = नीचे
forms-item-move-up-caption = ऊपर
forms-item-remove-caption = हटाएँ
forms-list-empty = यहाँ अभी कुछ नहीं है।
forms-option-none = कोई नहीं
forms-row-add = {$field} में पंक्ति जोड़ें
forms-row-label = पंक्ति {$index}
forms-row-move-down = {$field} की पंक्ति {$index} को नीचे ले जाएँ
forms-row-move-up = {$field} की पंक्ति {$index} को ऊपर ले जाएँ
forms-row-remove = {$field} की पंक्ति {$index} हटाएँ
forms-tag-add = {$field} में आइटम जोड़ें
forms-tag-item = {$field} का आइटम {$index}
forms-tag-move-down = {$field} के आइटम {$index} को नीचे ले जाएँ
forms-tag-move-up = {$field} के आइटम {$index} को ऊपर ले जाएँ
forms-tag-remove = {$field} का आइटम {$index} हटाएँ
forms-unsupported-note = यह बिल्ड इस मान को संपादित नहीं कर सकता। यह जैसा संग्रहीत है वैसा दिखाया गया है और अपरिवर्तित छोड़ा गया है।
forms-version-unsupported = {$service} {$since} चाहिए, इंस्टॉल किया गया {$installed}

## Form validation
## Mirrors the schema constraints for immediate feedback. The server is the
## authority: a clean pass here is not a promise that apply will succeed.
forms-error-enum = सूचीबद्ध मानों में से एक चुनें।
forms-error-format-ip = यह मान्य ip पता नहीं है।
forms-error-integer = पूर्ण संख्या का उपयोग करें।
forms-error-max-length = अधिकतम {$max} वर्ण उपयोग करें।
forms-error-maximum = {$max} या उससे कम का उपयोग करें।
forms-error-min-length = कम से कम {$min} वर्ण उपयोग करें।
forms-error-minimum = {$min} या उससे अधिक का उपयोग करें।
forms-error-pattern = यह मान उस रूप से मेल नहीं खाता जो यह फ़ील्ड स्वीकार करता है।
forms-error-required = यह फ़ील्ड आवश्यक है।
forms-error-type = यह मान उस प्रकार का नहीं है जो यह फ़ील्ड रखता है।
