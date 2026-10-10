# needs-review: machine-drafted Bengali translation; not yet checked by a native speaker.
## detent web admin UI — bn
## Source: locales/en-US/web.ftl. Same ids, same placeables.

## Status bar
status-brand = detent
status-online = সিস্টেম অনলাইন
status-clock-label = utc
status-mode-label = মোড
theme-toggle-aria = লাইট ও ডার্ক মোড পরিবর্তন করুন
theme-toggle-title = লাইট / ডার্ক পরিবর্তন করুন

## catfu component layer
## Chrome the shared components render themselves. Content strings (field
## captions, table headers, banner copy) are supplied by the calling page.
component-countdown-remaining = অবশিষ্ট সময়
component-field-info = আরও তথ্য
component-modal-close = বন্ধ করুন
component-switch-off = বন্ধ
component-switch-on = চালু
component-table-empty = কোনো রেকর্ড নেই

## API failures
## docs/API.md: every failure is `{ code, message_id }`, and `message_id` is a
## Fluent id. src/api/messages.ts resolves it here; an id this build does not
## know falls back to `api-error-unknown`, so an id is never rendered raw.
##
## The first three are the console's own — a failure that never reached a
## server has no `message_id` to resolve. The rest mirror the ids the server
## sends, argument-free: locales/en-US/core.ftl interpolates `{$path}`,
## `{$reason}` and friends, and the API deliberately sends none of them.
api-error-network = কনসোল এই হোস্টে পৌঁছাতে পারেনি।
api-error-malformed = এই হোস্ট এমন একটি উত্তর পাঠিয়েছে যা কনসোল পড়তে পারেনি।
api-error-unknown = এই হোস্ট এমন একটি ব্যর্থতার কথা জানিয়েছে যার কোনো বিবরণ কনসোলের কাছে নেই।
core-edit-index-out-of-range = অভ্যন্তরীণ ত্রুটি: একটি সম্পাদনা ফাইলের বাইরের একটি লাইনকে নির্দেশ করেছে।
core-edit-line-break = মানে নতুন লাইন বা null বাইট থাকতে পারে না।
core-edit-unsupported = এই সম্পাদনা ফাইলের ফরম্যাটে প্রকাশ করা যায় না।
core-model-shape = প্রদত্ত কনফিগারেশন প্রত্যাশিত গঠনের নয়।
core-model-unrepresentable = এই ফাইলে এমন কিছু আছে যা সম্পাদক উপস্থাপন করতে পারে না।
core-parse-malformed = এই ফাইল তার মডিউল যে ফরম্যাট আশা করে তার সঙ্গে মেলে না।
ops-audit-failed = অডিট লগ পড়া যায়নি।
ops-audit-unavailable = অডিট লগ লেখা যায়নি, তাই অপারেশন প্রত্যাখ্যান করা হয়েছে।
ops-denied = আপনার এটি করার অনুমতি নেই।
ops-hash-conflict = পড়ার পর ফাইলটি ডিস্কে বদলে গেছে; এটি আবার পড়ুন এবং পুনরায় চেষ্টা করুন।
ops-check-failed = বাহ্যিক ভ্যালিডেটর প্রার্থীকে প্রত্যাখ্যান করেছে।
ops-invalid-model = ওই কনফিগারেশন বৈধ নয়।
ops-no-service = এই মডিউল এই হোস্টে কোনো সার্ভিস নিয়ন্ত্রণ করে না, তাই এটি রিস্টার্ট করা যায় না।
ops-no-target = এই মডিউল এই হোস্টে কোনো ফাইল পরিচালনা করে না।
ops-privsep-failed = সুবিধাপ্রাপ্ত হেল্পার অনুরোধ প্রত্যাখ্যান করেছে বা সম্পন্ন করতে পারেনি।
ops-service-failed = সার্ভিসের কাজ সম্পন্ন হয়নি।
ops-unknown-module = এই বিল্ডে ওই নামে কোনো মডিউল নেই।
ops-unsupported = এটি এই বিল্ডে সমর্থিত নয়।
ops-commit-pending = আরেকটি commit-confirm উইন্ডো ইতিমধ্যেই অপেক্ষমাণ।
ops-update-running = একটি আপডেট ইতিমধ্যেই চলছে; এটি শেষ হওয়া পর্যন্ত অপেক্ষা করুন, তারপর চলমান সংস্করণ দেখুন।
ops-update-tag-invalid = এটি কোনো রিলিজ সংস্করণ নয়; এটি দেখতে v1.2.3-এর মতো হতে হবে।
ops-update-not-newer = ওই রিলিজ চলমান সংস্করণের চেয়ে নতুন নয়; কিছুই শুরু করা হয়নি।
ops-no-backup = commit-confirm-এর জন্য সংরক্ষিত ব্যাকআপ লাগে; কিছুই বদলানো হয়নি।
ops-arm-failed-restored = commit-confirm সক্রিয় করা যায়নি, তাই পরিবর্তনটি পূর্বাবস্থায় ফেরানো হয়েছে; আগের বিষয়বস্তু ফিরে এসেছে।
ops-arm-failed-unrestored = commit-confirm সক্রিয় করা যায়নি এবং পরিবর্তনটি পূর্বাবস্থায় ফেরানো যায়নি; নতুন বিষয়বস্তু এখনও ডিস্কে আছে। এখনই আগের ব্যাকআপ পুনরুদ্ধার করুন।
ops-target-missing = পরিচালিত ফাইলটি নেই; এটি তৈরি করুন (এর প্যাকেজ ইনস্টল করুন বা হাতে তৈরি করুন), তারপর আবার চেষ্টা করুন।
web-api-unexpected-outcome = অপারেশন সম্পন্ন হয়েছে কিন্তু তার ফলাফল প্রদর্শন করা যায়নি।
web-auth-ambiguous-credentials = সেশন কুকি অথবা বেয়ারার টোকেন পাঠান, দুটো একসঙ্গে নয়।
web-auth-argon2-params = কনফিগার করা argon2 প্যারামিটার ব্যবহারযোগ্য নয়।
web-auth-busy = অনেক বেশি সাইন-ইন চলছে; একটু অপেক্ষা করে আবার চেষ্টা করুন।
web-auth-csrf-rejected = এই অনুরোধ তার ক্রস-সাইট যাচাই পাস করেনি; পেজ রিলোড করে আবার চেষ্টা করুন।
web-auth-entropy-unavailable = সিস্টেমের র‍্যান্ডম নম্বর জেনারেটর ব্যর্থ হয়েছে, তাই কোনো ক্রেডেনশিয়াল ইস্যু করা যায়নি।
web-auth-hash-failed = পাসওয়ার্ডের হ্যাশ তৈরি করা যায়নি।
web-auth-invalid-credentials = ব্যবহারকারীর নাম, পাসওয়ার্ড বা কোড সঠিক ছিল না।
web-auth-password-change-required = অন্য কিছু করার আগে আপনার পাসওয়ার্ড বদলান।
web-auth-password-too-long = পাসওয়ার্ডে সর্বোচ্চ ১২৮টি অক্ষর থাকতে পারে।
web-auth-password-too-short = পাসওয়ার্ডে কমপক্ষে ১২টি অক্ষর থাকতে হবে।
web-auth-password-unchanged = নতুন পাসওয়ার্ড বর্তমান পাসওয়ার্ড থেকে আলাদা হতে হবে।
web-auth-rate-limited = অনেক বেশি চেষ্টা হয়েছে; একটু অপেক্ষা করে আবার চেষ্টা করুন।
web-auth-session-limit = অনেক বেশি সেশন খোলা আছে; একটির মেয়াদ শেষ হওয়া পর্যন্ত অপেক্ষা করে আবার সাইন ইন করুন।
web-auth-store-malformed = এই হোস্টের একটি ক্রেডেনশিয়াল ফাইল বৈধ নয়।
web-auth-store-unreadable = এই হোস্টের একটি ক্রেডেনশিয়াল ফাইল পড়া যায়নি।
web-auth-store-unwritable = এই হোস্টের একটি ক্রেডেনশিয়াল ফাইল লেখার জন্য প্রস্তুত করা যায়নি।
web-auth-store-write-failed = এই হোস্টের একটি ক্রেডেনশিয়াল ফাইল লেখা যায়নি।
web-auth-token-limit = এই হোস্টে ইতিমধ্যেই api টোকেনের সর্বোচ্চ সংখ্যা আছে।
web-auth-token-unknown = ওই api টোকেন নেই, বাতিল করা হয়েছে, অথবা মেয়াদোত্তীর্ণ হয়েছে।
web-auth-totp-secret-invalid = ওই অথেন্টিকেটর সিক্রেট বৈধ base32 নয়।
web-auth-unauthenticated = এটি করতে সাইন ইন করুন।
web-auth-user-exists = ওই নামে একজন ব্যবহারকারী ইতিমধ্যে আছেন।
web-auth-user-name-invalid = ওই ব্যবহারকারীর নাম ব্যবহারযোগ্য নয়; `a-z`, `0-9`, `.`, `_` বা `-` থেকে ১ থেকে ৩২টি অক্ষর ব্যবহার করুন, যা একটি অক্ষর বা অঙ্ক দিয়ে শুরু হবে।
web-auth-user-unknown = ওই নামে কোনো ব্যবহারকারী নেই।
web-cert-renew-not-acme = নবায়নের জন্য detent.toml-এ `tls.bootstrap = "acme"` লাগে।
web-cert-renew-unavailable = acme ক্লায়েন্ট নবায়নের অনুরোধ পায়নি; পরে আবার চেষ্টা করুন।
web-denied-scope = এই ক্রেডেনশিয়ালে ওই কাজের জন্য প্রয়োজনীয় স্কোপ নেই।
web-engine-stopped = অপারেশন ইঞ্জিন আর চলছে না; সার্ভিস ফিরে এলে আবার চেষ্টা করুন।
web-update-not-checked = এই হোস্টে এখনও কোনো আপডেট যাচাই চলেনি; root হিসেবে `detent update --check` চালান।
web-request-malformed = অনুরোধের বডি এই এন্ডপয়েন্ট যে গঠন আশা করে তার নয়।
web-request-too-deep = অনুরোধের বডি অতিরিক্ত গভীরভাবে নেস্ট করা।

## Sign in
login-title = সাইন ইন
login-panel-label = সেশন
login-username-label = ব্যবহারকারীর নাম
login-password-label = পাসওয়ার্ড
login-totp-label = অথেন্টিকেটর কোড
login-totp-description = এই অ্যাকাউন্টের জন্য নিবন্ধিত অথেন্টিকেটর থেকে ছয় অঙ্কের কোড।
login-totp-reveal = অথেন্টিকেটর কোড ব্যবহার করুন
login-submit = সাইন ইন
login-submitting = সাইন ইন হচ্ছে
login-retry-after = অনেক বেশি চেষ্টা হয়েছে; {$seconds} সেকেন্ড অপেক্ষা করে আবার চেষ্টা করুন।

## Change password
password-change-title = আপনার পাসওয়ার্ড বদলান
password-change-panel-label = পাসওয়ার্ড
password-change-intro = অন্য কিছু করার আগে এই অ্যাকাউন্টকে একটি নতুন পাসওয়ার্ড সেট করতে হবে।
password-change-current-label = বর্তমান পাসওয়ার্ড
password-change-new-label = নতুন পাসওয়ার্ড
password-change-new-description = ১২ থেকে ১২৮টি অক্ষর; যেকোনো অক্ষর অনুমোদিত।
password-change-confirm-label = নতুন পাসওয়ার্ড নিশ্চিত করুন
password-change-mismatch = নতুন পাসওয়ার্ড দুটি একই নয়।
password-change-submit = পাসওয়ার্ড বদলান
password-change-submitting = পাসওয়ার্ড বদলানো হচ্ছে

## Session and scope
auth-checking = এই সেশন যাচাই করা হচ্ছে
auth-sign-out = সাইন আউট
scope-gate-read-only = এই সেশনে কেবল পড়ার অ্যাক্সেস আছে; এটি এই হোস্টে কিছুই বদলাতে পারে না।
scope-gate-signed-out = এই হোস্টে কিছু বদলাতে সাইন ইন করুন।

## Navigation
nav-label = বিভাগ
nav-dashboard = ড্যাশবোর্ড
nav-modules = মডিউল
nav-services = সার্ভিস
nav-backups = ব্যাকআপ
nav-audit = অডিট
nav-certificates = সার্টিফিকেট
nav-settings = সেটিংস

## Routed pages
## Certificates and settings are still named placeholders: neither has an API
## to drive. Certificates waits on Phase 6 (ACME); settings waits on the user
## and token endpoints.
page-placeholder-body = এই বিভাগটি এখনও তৈরি হয়নি।
page-dashboard-title = ড্যাশবোর্ড
page-modules-title = মডিউল
page-module-detail-title = মডিউল {$module}
page-services-title = সার্ভিস
page-backups-title = ব্যাকআপ
page-audit-title = অডিট লগ
page-certificates-title = সার্টিফিকেট
page-settings-title = সেটিংস
page-not-found-title = এমন কোনো পেজ নেই
page-not-found-body = ওই ঠিকানা এই কনসোলের কোনো কিছুর নাম নয়।
page-not-found-home = ড্যাশবোর্ডে যান

## Pending commit
pending-commit-message = একটি কনফিগারেশন পরিবর্তন নিশ্চিতকরণের অপেক্ষায় আছে; এই উইন্ডো বন্ধ হলে এটি নিজে থেকেই রোলব্যাক হয়ে যায়।
pending-commit-countdown-label = নিশ্চিত করার জন্য অবশিষ্ট সময়
pending-commit-confirm = পরিবর্তন নিশ্চিত করুন
pending-commit-confirming = নিশ্চিত করা হচ্ছে…

## Shared page states
## Every section is a query away from its data, so loading, failure and "this
## host has none of these" are shared rather than re-worded per page.
state-loading = লোড হচ্ছে
state-unknown = অজানা
value-no = না
value-yes = হ্যাঁ

## Dashboard
dashboard-host-panel = হোস্ট
dashboard-host-hostname = হোস্টনেম
dashboard-host-os = অপারেটিং সিস্টেম
dashboard-host-init = init সিস্টেম
dashboard-host-distro = ডিস্ট্রিবিউশন
dashboard-host-ram = মেমরি
dashboard-host-network-backend = নেটওয়ার্ক ব্যাকএন্ড
dashboard-host-resolver-backend = রিজলভার ব্যাকএন্ড
dashboard-host-notes = শনাক্তকরণ টীকা
dashboard-cert-panel = সার্টিফিকেট
dashboard-cert-fingerprint = ফিংগারপ্রিন্ট
dashboard-cert-expires = মেয়াদ শেষ
dashboard-cert-lifetime-used = ব্যবহৃত মেয়াদ
dashboard-cert-expired = মেয়াদ শেষ হয়ে গেছে; এই সার্টিফিকেট বদলান।
dashboard-cert-expiring-soon = ৩০ দিনের মধ্যে মেয়াদ শেষ হবে; নবায়নের পরিকল্পনা করুন।
dashboard-cert-half = সার্টিফিকেটের মেয়াদের অর্ধেক ব্যবহৃত হয়েছে; নবায়ন নির্ধারিত আছে।
dashboard-cert-quarter = সার্টিফিকেটের মেয়াদের তিন-চতুর্থাংশ ব্যবহৃত হয়েছে; শীঘ্রই নবায়ন করুন।
cert-renew-panel = নবায়ন
cert-renew-now = এখনই নবায়ন করুন
cert-renew-requested = নবায়নের অনুরোধ করা হয়েছে। CA ইস্যু করলেই নতুন সার্টিফিকেট ইনস্টল হবে।
dashboard-modules-panel = মডিউল
dashboard-modules-count = {$count ->
    [one] {$count}টি মডিউল এই বিল্ডে কম্পাইল করা আছে।
   *[other] {$count}টি মডিউল এই বিল্ডে কম্পাইল করা আছে।
}
dashboard-audit-panel = সাম্প্রতিক কার্যকলাপ
dashboard-view-all = সব দেখুন
dashboard-update-panel = আপডেট
dashboard-update-current = চলমান সংস্করণ
dashboard-update-published = প্রকাশিত
dashboard-update-up-to-date = এই বিল্ডের জন্য কোনো নতুন রিলিজ দেওয়া হচ্ছে না।
dashboard-update-available = এই বিল্ডের জন্য রিলিজ {$tag} পাওয়া যাচ্ছে।
dashboard-update-security = এই রিলিজ নিরাপত্তা আপডেট হিসেবে চিহ্নিত; এটি এজ গেট এড়িয়ে যায়।
dashboard-update-install = {$tag} ইনস্টল করুন
dashboard-update-confirm-title = এই আপডেট ইনস্টল করবেন?
dashboard-update-confirm-body = এটি ব্যাকগ্রাউন্ডে {$tag} ইনস্টল করা শুরু করে। ইনস্টল হলে detent সার্ভিস রিস্টার্ট হয় এবং পেজের সংযোগ বিচ্ছিন্ন হয়ে আবার যুক্ত হতে পারে; রিস্টার্ট করা সার্ভিস সুস্থ না থাকলে আপডেট রোলব্যাক হয়ে যায়।
dashboard-update-confirm-action = ইনস্টল করুন
dashboard-update-confirm-cancel = বাতিল করুন
dashboard-update-started = {$version}-এ আপডেট ব্যাকগ্রাউন্ডে শুরু হয়েছে। ইনস্টল হলে সার্ভিস রিস্টার্ট হয় এবং সুস্থ না থাকলে রোলব্যাক হয়; ফলাফল চলমান সংস্করণে দেখা যায়।

## Modules
modules-panel-label = ইনস্টল করা মডিউল
modules-col-module = মডিউল
modules-col-targets = ফাইল
modules-col-services = সার্ভিস
modules-col-commit-confirm = commit-confirm
modules-commit-confirm-required = আবশ্যক
modules-commit-confirm-not-required = আবশ্যক নয়
modules-empty = এই বিল্ডে কোনো মডিউল কম্পাইল করা নেই।
modules-none = কিছু নেই

## One module
module-about-panel = মডিউল
module-configuration-panel = কনফিগারেশন
module-upstream-label = আপস্ট্রিম অনুসরণ করে
module-targets-label = ফাইল
module-services-label = সার্ভিস
module-current-hash-label = ডিস্কে ডাইজেস্ট
module-security-notes-label = নিরাপত্তা টীকা
module-model-missing = এই মডিউলের ফাইল এই হোস্টে এখনও নেই। নিচের ফর্ম মডিউলের নিজস্ব ডিফল্ট থেকে শুরু হয়, এবং প্রয়োগ করলে ফাইলটি তৈরি হয়।
module-action-validate = যাচাই করুন
module-action-plan = পরিকল্পনা
module-action-apply = প্রয়োগ করুন
module-action-discard = সম্পাদনা বাতিল করুন
module-busy = কাজ চলছে
module-validate-clean = এই কনফিগারেশন এই হোস্টের চালানো প্রতিটি যাচাই পাস করেছে।
module-plan-title = পরিকল্পিত পরিবর্তন
module-plan-no-change = এই কনফিগারেশন ডিস্কে যা আছে তার সঙ্গে মেলে; প্রয়োগ করার কিছু নেই।
module-plan-diff-label = diff
module-plan-checks-label = আপস্ট্রিম যাচাই
module-plan-check-passed = উত্তীর্ণ
module-plan-check-failed = ব্যর্থ
module-plan-check-exit = exit {$code}
module-plan-services-label = এতে যে সার্ভিস প্রভাবিত হবে
module-plan-apply = এই পরিবর্তন প্রয়োগ করুন
module-apply-title = এই পরিবর্তন প্রয়োগ করবেন?
module-apply-body = এটি এই হোস্টে {$path} লেখে। আগে বর্তমান বিষয়বস্তুর ব্যাকআপ নেওয়া হয়।
module-apply-commit-confirm = এই মডিউল অ্যাডমিনিস্ট্রেটরকে বাইরে আটকে দিতে পারে, তাই পরিবর্তনটি একটি commit-confirm উইন্ডো সক্রিয় করে: সময়সীমার আগে নিশ্চিত না করলে এটি নিজে থেকেই রোলব্যাক হয়ে যায়।
module-apply-service-label = এরপর
module-apply-service-none = সার্ভিস যেমন আছে তেমন রাখুন
module-apply-cancel = বাতিল করুন
module-applied = পরিবর্তনটি {$path}-এ লেখা হয়েছে।
module-applied-created = {$path} ছিল না এবং তৈরি করা হয়েছে।
module-mounts-off = নতুন fstab এন্ট্রি মাউন্ট করা হয়নি ([mounts] activate_new_entries বন্ধ); সেগুলো পরবর্তী বুট বা মাউন্টে কার্যকর হয়।
module-mounts-error = কোনো মাউন্ট ইউনিট চালু হয়নি: {$reason}
module-mounts-none = মাউন্ট করার মতো কোনো নতুন fstab এন্ট্রি নেই।
module-mounts-units = নতুন fstab এন্ট্রির মাউন্ট ইউনিট:
module-mount-state-mounted = মাউন্ট হয়েছে
module-mount-state-already-mounted = আগে থেকেই মাউন্ট করা
module-mount-state-pending = এখনও মাউন্ট হচ্ছে
module-mount-state-failed = ব্যর্থ
module-mount-state-protected = প্রত্যাখ্যাত: সুরক্ষিত পাথ
module-mount-state-stopped = আনমাউন্ট হয়েছে
module-cancel = বাতিল করুন

## Services
services-panel-label = সার্ভিস
services-col-module = মডিউল
services-col-unit = ইউনিট
services-col-state = অবস্থা
services-col-enabled = বুটে
services-col-since = থেকে
services-col-actions = কাজ
services-state-active = সক্রিয়
services-state-inactive = নিষ্ক্রিয়
services-state-failed = ব্যর্থ
services-state-activating = চালু হচ্ছে
services-state-deactivating = বন্ধ হচ্ছে
services-state-unknown = অজানা
services-action-restart = রিস্টার্ট
services-action-reload = রিলোড
services-action-start = চালু করুন
services-action-stop = বন্ধ করুন
services-acted = {$unit}: {$detail}
services-empty = এই বিল্ডের কোনো মডিউল এই হোস্টে কোনো সার্ভিস নিয়ন্ত্রণ করে না।
services-confirm-title = {$unit}: {$action}?
services-confirm-body = এটি চলমান সার্ভিসে তাৎক্ষণিকভাবে কাজ করে।
services-confirm-cancel = বাতিল করুন

## Backups
backups-col-name = ব্যাকআপ
backups-col-created = নেওয়া হয়েছে
backups-col-size = আকার
backups-col-digest = ডাইজেস্ট
backups-col-actions = কাজ
backups-action-restore = পুনরুদ্ধার করুন
backups-confirm-title = এই ব্যাকআপ পুনরুদ্ধার করবেন?
backups-confirm-body = এটি {$target}-কে সংরক্ষিত কপি দিয়ে প্রতিস্থাপন করে। আগে বর্তমান বিষয়বস্তুর ব্যাকআপ নেওয়া হয়।
backups-confirm-cancel = বাতিল করুন
backups-restored = ব্যাকআপ পুনরুদ্ধার করা হয়েছে।
backups-empty = এই মডিউলের এখনও কিছুই ব্যাকআপ নেওয়া হয়নি।
backups-module-panel = {$module} ব্যাকআপ

## Audit log
audit-panel-label = অডিট লগ
audit-col-when = কখন
audit-col-who = কলার
audit-col-how = ক্রেডেনশিয়াল
audit-col-op = অপারেশন
audit-col-module = মডিউল
audit-col-result = ফলাফল
audit-filter-module-label = মডিউল
audit-filter-who-label = কলার
audit-filter-limit-label = সারি
audit-filter-apply = ফিল্টার করুন
audit-filter-clear = মুছুন
audit-empty = এই হোস্টে এখনও কিছুই রেকর্ড করা হয়নি।
audit-result-ok = ঠিক
audit-result-denied = প্রত্যাখ্যাত
audit-result-error = ব্যর্থ
audit-identity-local-user = স্থানীয় ব্যবহারকারী
audit-identity-session = সেশন
audit-identity-token = api টোকেন
audit-op-list-modules = মডিউল তালিকাভুক্ত করুন
audit-op-get-module = মডিউল পড়ুন
audit-op-validate = যাচাই করুন
audit-op-plan = পরিকল্পনা
audit-op-apply = প্রয়োগ করুন
audit-op-confirm-commit = কমিট নিশ্চিত করুন
audit-op-rollback-commit = কমিট রোলব্যাক করুন
audit-op-list-backups = ব্যাকআপ তালিকাভুক্ত করুন
audit-op-restore = ব্যাকআপ পুনরুদ্ধার করুন
audit-op-service-status = সার্ভিসের অবস্থা পড়ুন
audit-op-service-action = সার্ভিসে কাজ করুন
audit-op-host-profile = হোস্ট প্রোফাইল পড়ুন
audit-op-audit-query = অডিট লগ পড়ুন
audit-op-cert-status = সার্টিফিকেটের অবস্থা পড়ুন
audit-op-update-status = আপডেটের অবস্থা পড়ুন
audit-op-cert-renew = সার্টিফিকেট নবায়ন করুন
audit-op-update-apply = আপডেট ইনস্টল করুন
## Schema-driven module forms
## Chrome the form engine (web/src/forms) renders around a module's schema.
## Field captions come from the schema's own property names, and a field's
## tooltip and recommendation are Fluent ids in the *module's* locale file, not
## here — a missing one degrades to no tooltip and is never rendered raw.
forms-advanced-toggle = উন্নত
forms-badge-security-high = উচ্চ নিরাপত্তা প্রভাব
forms-badge-deprecated = {$version}-এ অপ্রচলিত
forms-diagnostic-at-field = {$field}: {$message}
forms-diagnostic-unknown = এই হোস্ট এমন একটি যাচাইয়ের ফলাফল জানিয়েছে যার কোনো বিবরণ এই বিল্ডে নেই ({$id})।
forms-item-add-caption = যোগ
forms-item-move-down-caption = নিচে
forms-item-move-up-caption = ওপরে
forms-item-remove-caption = মুছুন
forms-list-empty = এখানে এখনও কিছু নেই।
forms-option-none = কিছু নেই
forms-row-add = {$field}-এ একটি সারি যোগ করুন
forms-row-label = সারি {$index}
forms-row-move-down = {$field}-এর সারি {$index} নিচে সরান
forms-row-move-up = {$field}-এর সারি {$index} ওপরে সরান
forms-row-remove = {$field}-এর সারি {$index} সরান
forms-tag-add = {$field}-এ একটি আইটেম যোগ করুন
forms-tag-item = {$field}-এর আইটেম {$index}
forms-tag-move-down = {$field}-এর আইটেম {$index} নিচে সরান
forms-tag-move-up = {$field}-এর আইটেম {$index} ওপরে সরান
forms-tag-remove = {$field}-এর আইটেম {$index} সরান
forms-unsupported-note = এই বিল্ড এই মান সম্পাদনা করতে পারে না। এটি যেভাবে সংরক্ষিত আছে সেভাবেই দেখানো হয়েছে এবং অপরিবর্তিত রাখা হয়েছে।
forms-version-unsupported = {$service} {$since} লাগে, ইনস্টল করা {$installed}

## Form validation
## Mirrors the schema constraints for immediate feedback. The server is the
## authority: a clean pass here is not a promise that apply will succeed.
forms-error-enum = তালিকাভুক্ত মানগুলোর একটি বেছে নিন।
forms-error-format-ip = এটি বৈধ ip ঠিকানা নয়।
forms-error-integer = একটি পূর্ণসংখ্যা ব্যবহার করুন।
forms-error-max-length = সর্বোচ্চ {$max}টি অক্ষর ব্যবহার করুন।
forms-error-maximum = {$max} বা তার কম ব্যবহার করুন।
forms-error-min-length = কমপক্ষে {$min}টি অক্ষর ব্যবহার করুন।
forms-error-minimum = {$min} বা তার বেশি ব্যবহার করুন।
forms-error-pattern = এই মান এই ফিল্ড যে রূপ গ্রহণ করে তার সঙ্গে মেলে না।
forms-error-required = এই ফিল্ড আবশ্যক।
forms-error-type = এই মান এই ফিল্ড যে ধরনের মান ধারণ করে তা নয়।
