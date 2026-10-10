# needs-review: machine-drafted Bengali translation; not yet checked by a native speaker.
## detent CLI — bn
## Source: locales/en-US/cli.ftl. Same ids, same placeables. Identifiers —
## module ids, paths, unit names, digests, enum wire names — are interpolated
## verbatim and are not translated.

## severity words, prefixed to every rendered diagnostic
cli-severity-error = ত্রুটি
cli-severity-warning = সতর্কতা
cli-severity-recommendation = টীকা

## yes/no, used wherever a flag is rendered
cli-yes = হ্যাঁ
cli-no = না

## progress notes, printed on stderr under --verbose
cli-note-settings = লোকেল {$locale}, স্টেট রুট {$state}, কনফিগ {$config}
cli-note-operation = {$module}-এর জন্য {$operation} চলছে

## failures that stop a command before the operations layer sees it
cli-bad-stdin = stdin থেকে মডেল পড়া যায়নি: {$reason}
cli-bad-json = stdin-এর মডেল বৈধ json নয়: {$reason}
cli-bad-hash = `{$value}` ৬৪টি হেক্স অক্ষরের sha-256 ডাইজেস্ট নয়।
cli-start-failed = সুবিধাপ্রাপ্ত হেল্পার চালু করা যায়নি: {$reason}
cli-monitor-stop = সুবিধাপ্রাপ্ত হেল্পার ঠিকভাবে বন্ধ হয়নি: {$reason}
cli-monitor-busy = অন্য একটি detent মনিটর ইতিমধ্যে এই স্টেট রুটের মালিক; ওয়েব UI-এর মাধ্যমে আবার চেষ্টা করুন বা `detent serve` চালান।
cli-monitor-lock-unavailable = {$path}-এর স্টেট লক নেওয়া যাচ্ছে না, তাই এই কমান্ড কিছুই বদলাতে পারে না; এটি এমন ব্যবহারকারী হিসেবে চালান যিনি ওই ডিরেক্টরিতে লিখতে পারেন, অথবা --state-root দিন।
cli-commit-recovered = অনিশ্চিত কমিট {$commit} পুনরুদ্ধার করা হয়েছে; {$failures}টি ব্যর্থতাসহ {$restored}টি লক্ষ্য পুনরুদ্ধার করা হয়েছে।
cli-commit-confirm-needs-serve = এই মডিউলের জন্য commit-confirm লাগে; নিশ্চিতকরণ উইন্ডো কার্যকর থাকার জন্য ওয়েব UI বা `detent serve` ব্যবহার করুন।
cli-config-load-failed = {$path}-এর কনফিগারেশন লোড করা যায়নি: {$reason}
cli-no-command = কোনো কমান্ড দেওয়া হয়নি।

## self-test probe and self-update (PLAN §2.9)
cli-self-test = সংস্করণ {$version} ফিচার {$features}
cli-update-available = আপডেট পাওয়া যাচ্ছে: {$tag}, প্রকাশিত {$published}
cli-update-security-available = নিরাপত্তা আপডেট পাওয়া যাচ্ছে: {$tag}, প্রকাশিত {$published}
cli-update-none = কোনো আপডেট নেই (বর্তমান {$current})
cli-update-held-young = {$tag} {$current}-এর চেয়ে নতুন কিন্তু {$days} দিনের কম পুরোনো; এজ গেট এটি আটকে রেখেছে
cli-update-held-rejected = {$tag} {$current}-এর চেয়ে নতুন কিন্তু এই হোস্টে রোলব্যাক করা হয়েছিল; এটি বাদ দেওয়া হয়েছে
cli-verify-bundle-ok = {$file} {$tag}-এর জন্য প্রত্যয়িত
cli-update-failed = আপডেট ব্যর্থ: {$reason}
cli-update-installed = {$tag} ইনস্টল হয়েছে; এটি যে বাইনারি প্রতিস্থাপন করেছে তা {$previous}-এ রাখা আছে
cli-update-not-restarted = সার্ভিস রিস্টার্ট হয়নি, তাই নতুন বাইনারি এখনও চলছে না: {$reason}
cli-update-rolled-back = রোলব্যাক করা হয়েছে: {$reason}
cli-update-rollback-failed = আপডেট ব্যর্থ হয়েছে ({$reason}) এবং রোলব্যাকও ব্যর্থ হয়েছে ({$error}); এই হোস্টে মনোযোগ প্রয়োজন

## config
cli-module-line = {$id}  {$name}
cli-no-model = এই মডিউল এখনও এই হোস্টে কোনো ফাইল পরিচালনা করে না, তাই দেখানোর মতো কোনো মডেল নেই।
cli-valid = এই কনফিগারেশন বৈধ।
cli-plan-no-change = {$module} ইতিমধ্যে {$path}-এ যা আছে তা-ই; কিছুই বদলাবে না।
cli-plan-service = এটি প্রয়োগ করলে {$unit} প্রভাবিত হবে।
cli-plan-hash = ফাইলের হ্যাশ এখন {$hash}; এটি --expect-hash হিসেবে দিন যাতে মাঝপথে ঘটা সম্পাদনা প্রত্যাখ্যাত হয়।
cli-check-ran = আপস্ট্রিম ভ্যালিডেটর {$program} চলেছে; উত্তীর্ণ: {$passed}। {$detail}
cli-check-skipped = আপস্ট্রিম ভ্যালিডেটর {$program} চলেনি। {$detail}
cli-applied = {$module} {$path}-এ লেখা হয়েছে।
cli-applied-hash = এর হ্যাশ ছিল {$prev} এবং এখন {$new}; ব্যাকআপ রাখা হয়েছে: {$backup}
cli-mounts-off = mounts: সক্রিয়করণ বন্ধ ([mounts] activate_new_entries); নতুন fstab এন্ট্রি পরবর্তী বুট বা মাউন্টে কার্যকর হয়।
cli-mounts-error = mounts: কোনো মাউন্ট ইউনিট চালু হয়নি: {$reason}
cli-mounts-none = mounts: মাউন্ট করার মতো কোনো নতুন fstab এন্ট্রি নেই।
cli-mounts-unit = মাউন্ট {$mountpoint} ({$unit}): {$state}
cli-mounts-unit-detail = মাউন্ট {$mountpoint} ({$unit}): {$state}: {$detail}
cli-commit-armed = কমিট {$id} {$seconds} সেকেন্ডের মধ্যে, অর্থাৎ {$deadline}-এর মধ্যে, নিশ্চিত করতে হবে, নইলে এটি রোলব্যাক হবে।
cli-commit-confirmed = কমিট {$id} নিশ্চিত করা হয়েছে এবং এটি রোলব্যাক হবে না।
cli-commit-rolled-back = কমিট {$id} রোলব্যাক করা হয়েছে; {$targets}টি লক্ষ্য আগের অবস্থায় ফেরানো হয়েছে।

## backups
cli-no-backups = এই মডিউলের জন্য এখনও কোনো ব্যাকআপ রাখা হয়নি।
cli-backup-line = {$id}  {$name}  {$bytes} বাইট  {$digest}
cli-restored = লক্ষ্য {$target} আগের অবস্থায় ফেরানো হয়েছে এবং এখন এর হ্যাশ {$hash}।

## services
cli-service-status = {$unit} {$state}; বুটে চালু হয়: {$enabled}
cli-serviced = {$unit}-কে {$action} করতে বলা হয়েছে; এখন চলছে: {$active}

## host
cli-host-profile = {$hostname}: {$os}, init {$init}, {$ram} mib র‍্যাম
cli-host-service-version = ইনস্টল করা {$service}-এর সংস্করণ {$version}
cli-host-backends = নেটওয়ার্ক ব্যাকএন্ড {$network}, রিজলভার ব্যাকএন্ড {$resolver}, ডিস্ট্রো {$distro} {$version}
cli-host-note = শনাক্তকরণ টীকা: {$note}

## audit
cli-no-audit = অডিট লগে মিলে যাওয়া কোনো রেকর্ড নেই।
cli-audit-line = {$ts}  {$who}  {$op}  {$module}  {$result}  {$error}
cli-audit-verified = অডিট চেইন রেকর্ড {$sequence} পর্যন্ত অক্ষত; হেড ডাইজেস্ট {$hash}
cli-audit-broken = অডিট চেইন যাচাই করা যায়নি: {$reason}

## --dryrun
cli-dryrun-apply = ড্রাই রান: {$module}-এর জন্য {$path}-এ এটিই লেখা হবে।
cli-dryrun-operation = ড্রাই রান: {$module}-এর জন্য {$operation} চলবে।
cli-dryrun-nothing = ড্রাই রান: কিছুই বদলানো হয়নি।
cli-dryrun-serve = ড্রাই রান: মনিটর ও ওয়ার্কার {$modules}টি মডিউল ও {$targets}টি লক্ষ্য নিয়ে, {$state}-কে রুট ধরে চালু হবে।
cli-dryrun-serve-mounts = ড্রাই রান: mounts apply-এর পর রানার নতুন fstab এন্ট্রির মাউন্ট ইউনিট চালু করবে (mounts.activate_new_entries = true)।
cli-dryrun-cert-renew = ড্রাই রান: {$address}-এর সার্ভারকে ({$name} হিসেবে) এখনই তার সার্টিফিকেট নবায়ন করতে বলা হবে; কিছু পাঠানো হয়নি।

## serve
cli-serve-monitor = ওয়ার্কার pid {$pid} হিসেবে চালু হয়েছে; সুবিধা ত্যাগ করা হয়েছে: {$dropped}
cli-serve-worker = ওয়ার্কার চলছে; এর http সার্ভার ফেজ ৪-এ আসবে। হ্যান্ডশেক: {$greeted}
cli-serve-failed = মনিটর ও ওয়ার্কার চালু করা যায়নি: {$reason}
cli-serve-stopped = জোড়াটি অপ্রত্যাশিতভাবে থেমে গেছে: {$reason} {$status}
cli-serve-privileged-port = পোর্ট {$port}-এর জন্য cap_net_bind_service বা মনিটরের দেওয়া সকেট লাগে, যার কোনোটিই এই বিল্ড সমর্থন করে না; ১০২৪ বা তার বেশি পোর্ট ব্যবহার করুন, অথবা সামনে একটি রিভার্স প্রক্সি বসান।
cli-serve-privilege-mode = কনফিগার করা সুবিধা মোড এই প্রসেসের সঙ্গে মেলে না, তাই সার্ভিস চালু হয়নি: {$reason}
cli-serve-acme-unsupported = এই বিল্ডে কোনো dns-01 প্রদানকারী নেই (ফিচার acme-dns-providers), তাই এটি acme সার্টিফিকেট পেতে পারে না; {$path}-এ tls.bootstrap "self-signed" সেট করুন।
cli-serve-acme-setting-missing = tls.bootstrap "acme", কিন্তু {$path}-এ {$setting} সেট করা নেই।
cli-serve-acme-path-outside = {$setting} ({$value}) স্টেট রুট {$root}-এর অধীনে নয়: সীমাবদ্ধ প্রসেসগুলো কেবল সেখানেই লেখে।
cli-serve-acme-credentials-dir = acme ক্রেডেনশিয়াল ডিরেক্টরি {$path} প্রস্তুত করা যায়নি: {$reason}
cli-serve-secrets-failed = সিক্রেট ফাইল {$path} প্রত্যাখ্যান করা হয়েছে: {$reason}
cli-serve-acme-secret-missing = acme.provider সেট করা আছে, কিন্তু {$path}-এর [acme] টেবিলে dns_provider সিক্রেট নেই।
cli-serve-acme-provider-invalid = acme.provider-এ দেওয়া dns-01 প্রদানকারী ব্যবহার করা যাচ্ছে না: {$reason}
cli-serve-acme-providers-not-built = এই বিল্ডে কোনো dns-01 প্রদানকারী নেই (ফিচার acme-dns-providers); {$path} থেকে [acme.provider] সরিয়ে দিন।
cli-serve-handshake-failed = ওয়ার্কার মনিটরের সঙ্গে তার হ্যান্ডশেক সম্পন্ন করতে পারেনি।
cli-serve-auth-failed = অ্যাকাউন্ট, টোকেন ও সেশন স্টোর খোলা যায়নি: {$reason}
cli-serve-tls-failed = tls সার্টিফিকেট প্রস্তুত করা যায়নি: {$reason}
cli-serve-cert-fingerprint = tls বুটস্ট্র্যাপ সার্টিফিকেটের ফিংগারপ্রিন্ট (sha-256): {$fingerprint}
cli-serve-web-failed = ওয়েব সার্ভার চালু হতে পারেনি: {$reason}
cli-serve-web-stopped = ওয়েব সার্ভার ঠিকভাবে বন্ধ হয়নি: {$reason}
cli-serve-listening = {$addr}-এ শুনছে
cli-serve-confinement-degraded = কনফাইনমেন্ট দুর্বল হয়েছে: {$detail}
cli-mcp-missing-token = {$var} সেট করা নেই; `detent token create` দিয়ে একটি তৈরি করুন এবং mcp সার্ভার চালুর আগে এক্সপোর্ট করুন।
cli-mcp-serve-failed = mcp সার্ভার চালু হতে পারেনি: {$reason}
cli-mcp-listening = mcp {$transport} পরিবেশন করছে
cli-mcp-http-needs-privsep = mcp http ট্রান্সপোর্ট root হিসেবে বা capabilities নিয়ে চলতে পারে না: নেটওয়ার্ক পার্সার root-তুল্য ক্ষমতা নিয়ে চলত; capabilities ছাড়া নন-root ব্যবহারকারী হিসেবে চালান অথবা stdio ট্রান্সপোর্ট ব্যবহার করুন।
cli-mcp-bind-not-loopback = mcp http বাইন্ড লুপব্যাক (127.0.0.1 বা ::1) হতে হবে; বেয়ারার তারের ওপর সাধারণ টেক্সটে যায়।
cli-dryrun-mcp = ড্রাই রান: mcp {$addr}-এ স্কোপ {$scope} সহ {$transport} পরিবেশন করবে।

## setup, user, token
cli-setup-exists = `{$name}` নামে একজন ব্যবহারকারী এই হোস্টে ইতিমধ্যে আছেন; ওভাররাইট করতে --force দিন।
cli-setup-created = অ্যাডমিনিস্ট্রেটর অ্যাকাউন্ট `{$name}` তৈরি করা হয়েছে।
cli-user-created = অ্যাকাউন্ট `{$name}` তৈরি করা হয়েছে।
cli-user-passwd = `{$name}`-এর পাসওয়ার্ড বদলানো হয়েছে।
cli-user-removed = অ্যাকাউন্ট `{$name}` সরানো হয়েছে।
cli-totp-uri = এটি আপনার অথেন্টিকেটর অ্যাপে যোগ করুন: {$uri}
cli-totp-secret = অথবা এই কী সেখানে টাইপ করুন: {$secret}
cli-totp-code-prompt = আপনার অথেন্টিকেটর থেকে কোড:
cli-totp-code-empty = কোড খালি থাকতে পারে না।
cli-totp-code-wrong = ওই কোড বৈধ নয়, তাই দ্বিতীয় ফ্যাক্টর চালু করা হয়নি।
cli-user-totp-enabled = `{$name}`-এর জন্য দ্বিতীয় ফ্যাক্টর চালু করা হয়েছে।
cli-totp-disable-prompt = `{$name}`-এর জন্য দ্বিতীয় ফ্যাক্টর বন্ধ করবেন? [y/N]
cli-totp-disable-cancelled = `{$name}`-এর জন্য দ্বিতীয় ফ্যাক্টর চালু রাখা হয়েছে।
cli-user-totp-disabled = `{$name}`-এর জন্য দ্বিতীয় ফ্যাক্টর বন্ধ করা হয়েছে।
cli-token-created = টোকেন {$id} ({$label}) তৈরি করা হয়েছে; এটি আর দেখানো হবে না: {$token}
cli-token-revoked = টোকেন {$id} বাতিল করা হয়েছে।
cli-token-no-tokens = কোনো টোকেন ইস্যু করা হয়নি।
cli-token-line = {$id}  {$label}  {$scopes}  {$created}  {$expires}
cli-credential-failed = অনুরোধ সম্পন্ন করা যায়নি: {$reason}
cli-audit-failed = পরিবর্তন করা হয়েছে, কিন্তু তার অডিট রেকর্ড লেখা যায়নি: {$reason}
cli-state-command-as-root = detent {$command} root হিসেবে চালানো উচিত নয়: এটি যে ফাইল লেখে সেগুলো root-এর মালিকানায় হবে এবং সার্ভিস সেগুলো পড়তে পারবে না। এটি সার্ভিস অ্যাকাউন্ট হিসেবে চালান: sudo -u {$account} detent {$command}

## cert status
cli-cert-source = উৎস: {$source}
cli-cert-fingerprint = ফিংগারপ্রিন্ট (sha-256): {$fingerprint}
cli-cert-not-after = মেয়াদ শেষ: {$not_after}
cli-cert-not-after-unknown = মেয়াদ শেষ: অজানা (সার্টিফিকেট পার্স হয়নি)।
cli-cert-lifetime = ব্যবহৃত মেয়াদ: {$percent} (সতর্কতা: {$warning})।
cli-cert-lifetime-no-warning = ব্যবহৃত মেয়াদ: {$percent} (কোনো সতর্কতা নেই)।
cli-cert-lifetime-unknown = ব্যবহৃত মেয়াদ: অজানা (সার্টিফিকেট পার্স হয়নি)।
cli-cert-missing = {$path}-এ কোনো সার্টিফিকেট সংরক্ষিত নেই; সার্ভারটি একবার চালু করুন যাতে সে একটি লেখে।
cli-cert-unreadable = {$path}-এর সার্টিফিকেট পড়া যায়নি: {$reason}

## cert renew
cli-cert-renew-requested = নবায়নের অনুরোধ করা হয়েছে: সার্ভার তার ACME ক্লায়েন্টকে এখনই নবায়ন করতে বলেছে। ফলাফল `detent cert status` দিয়ে দেখুন।
cli-cert-renew-token-refused = টোকেন প্রত্যাখ্যান করা হয়েছে (HTTP {$status}); এর জন্য write স্কোপ লাগে: `detent token create <name> --write`।
cli-cert-renew-not-acme = সার্ভার কোনো ACME প্রসেস চালায় না (`tls.bootstrap` `acme` নয়), তাই নবায়ন করার কিছু নেই।
cli-cert-renew-server-error = সার্ভার HTTP {$status} দিয়ে সাড়া দিয়েছে: {$message_id}
cli-cert-renew-server-error-bare = সার্ভার HTTP {$status} দিয়ে সাড়া দিয়েছে।
cli-cert-renew-unreachable = {$address}-এর সার্ভারের সঙ্গে যোগাযোগ করা যায়নি: {$reason}
cli-cert-renew-no-token = কোনো API টোকেন নেই: --token-file <path> দিন বা {$var} সেট করুন। write টোকেন `detent token create <name> --write` দিয়ে তৈরি করুন।
cli-cert-renew-bad-token = {$source}-এর টোকেন প্রত্যাখ্যান করা হয়েছে: {$reason}
cli-cert-renew-ca-unreadable = CA ফাইল {$path} পড়া যায়নি: {$reason}

## password entry (setup, user add, user passwd)
cli-password-prompt = পাসওয়ার্ড:
cli-password-confirm = পাসওয়ার্ড নিশ্চিত করুন:
cli-password-mismatch = পাসওয়ার্ড দুটি মেলেনি।
cli-password-empty = পাসওয়ার্ড খালি থাকতে পারে না।

## doctor
cli-status-ok = ঠিক
cli-status-warn = সতর্কতা
cli-status-fail = ব্যর্থ
cli-doctor-modules = এই বিল্ডে কম্পাইল করা মডিউল: {$detail}
cli-doctor-state-root = স্টেট ডিরেক্টরি {$detail}
cli-doctor-config = কনফিগারেশন ফাইল {$detail}
cli-doctor-privsep = সুবিধা পৃথকীকরণ একটি কার্যকর জোড়া ফর্ক করতে পারে: {$detail}
cli-doctor-landlock = landlock: {$detail}
cli-doctor-seccomp = seccomp: {$detail}
cli-doctor-confinement = স্যান্ডবক্স কনফাইনমেন্ট: {$detail}
cli-doctor-serve-confinement = সর্বশেষ serve চালুর সময়ের কনফাইনমেন্ট: {$detail}
cli-doctor-mounts = fstab apply-এর পর মাউন্ট সক্রিয়করণ: {$detail}
cli-doctor-privilege-mode = সুবিধা মোড: {$detail}
cli-doctor-service-account = সার্ভিস অ্যাকাউন্ট: {$detail}
cli-doctor-state-owner = স্টেট ডিরেক্টরির মালিক: {$detail}
cli-doctor-backups-dir = ব্যাকআপ ডিরেক্টরি: {$detail}
cli-doctor-polkit-rule = polkit নিয়ম: {$detail}
cli-doctor-polkit-daemon = polkit ডেমন: {$detail}
cli-doctor-unit-capabilities = সার্ভিস ইউনিটের পরিচয় ও capabilities: {$detail}
