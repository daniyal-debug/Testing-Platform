"""Generated remediation knowledge base — long-form fix guides keyed by finding id.

Authored and technical-accuracy-reviewed by a multi-agent workflow, then merged
here. Edit via that pipeline rather than by hand. Consumed by
:mod:`apk_sentinel.knowledge`.
"""
# fmt: off
KNOWLEDGE = {
    "android-debuggable": {
        "summary": "The release APK ships with android:debuggable=\"true\". This flag turns on the JDWP debugging bridge for the app's process, letting anyone attach a debugger to a production build and control it at runtime.",
        "why_it_matters": "With debuggable=true, an attacker who has USB/adb access (no root needed) can attach jdb or Android Studio to the running process, read and modify variables, dump process memory to extract keys/tokens/PII, invoke internal methods, and bypass client-side auth or license checks. It also permits `run-as <package>` shell access to the app's private data directory. This is a well-known, trivially exploited misconfiguration (CWE-489, Active Debug Code).",
        "fix_steps": [
            "Search AndroidManifest.xml (and any manifest overlays/flavors) for android:debuggable and delete the attribute entirely — never hardcode it.",
            "Let Gradle own the flag: debug builds automatically get debuggable=true, release builds default to false. Do not set isDebuggable/debuggable in the release buildType.",
            "Confirm no build flavor, CI step, or manifest-merger overlay re-injects android:debuggable=\"true\" (check the merged manifest, not just source).",
            "Enable R8/minify on release so debug metadata is stripped, then rebuild the signed release artifact.",
            "Verify the shipped APK/AAB reports debuggable=false before publishing."
        ],
        "code_example": "// app/build.gradle.kts  (Kotlin DSL, AGP 8.x)\nandroid {\n    buildTypes {\n        release {\n            isMinifyEnabled = true\n            isShrinkResources = true\n            // Do NOT set isDebuggable = true here — release must stay non-debuggable.\n            proguardFiles(\n                getDefaultProguardFile(\"proguard-android-optimize.txt\"),\n                \"proguard-rules.pro\"\n            )\n        }\n        getByName(\"debug\") {\n            isDebuggable = true   // debug-only; never applied to release\n        }\n    }\n}\n\n<!-- AndroidManifest.xml: the <application> tag must NOT contain android:debuggable -->\n<application\n    android:name=\".App\"\n    android:allowBackup=\"false\">\n    <!-- ... -->\n</application>",
        "how_to_verify": "Run `apkanalyzer manifest debuggable app-release.apk` and confirm it prints `false`. Alternatively `aapt dump xmltree app-release.apk AndroidManifest.xml` should show no `debuggable` attribute. As a live check, try `adb shell run-as com.example.app` against a device running the release build — it must be denied.",
        "references": [
            "https://developer.android.com/privacy-and-security/risks/android-debuggable",
            "https://developer.android.com/guide/topics/manifest/application-element#debug",
            "https://cwe.mitre.org/data/definitions/489.html",
            "https://mas.owasp.org/MASVS/09-MASVS-RESILIENCE/"
        ]
    },
    "app-backup-allowed": {
        "summary": "android:allowBackup defaults to true when unset, so the OS includes the app's private data in Android Auto Backup (cloud, to the user's Google Drive) and in device-to-device (D2D) transfer. On Android 11 and lower — or in any build that is debuggable — the data can additionally be pulled off with `adb backup` without root.",
        "why_it_matters": "Sensitive material stored in the app sandbox (SharedPreferences, SQLite databases, session tokens, cached PII) is only as safe as the backup policy. Auto Backup copies it to the user's Google Drive, widening exposure across devices and accounts, and D2D transfer carries it to a new device during setup. On devices running Android 11 or lower — or against a debuggable build on any version — an attacker with brief physical/USB access can also run `adb backup` to extract those files off an unrooted device and read them offline. Note the modern nuance: for apps targeting API 31+ running on Android 12+, `adb backup` now excludes app data by default (opt-in only via debuggable=true), so on current devices the cloud and D2D vectors are the primary concern rather than adb. CWE-530 (Exposure of Backup File); MASVS-STORAGE.",
        "fix_steps": [
            "Classify the data the app stores. If it holds credentials, tokens, or PII and you don't need cloud/D2D backup, set android:allowBackup=\"false\" — the simplest, safest baseline.",
            "Be aware allowBackup=\"false\" reliably disables cloud (Google Drive) backup, but on some OEM devices it does NOT disable device-to-device transfer. To also block D2D, declare android:dataExtractionRules (API 31+) with a <device-transfer> section that excludes the sensitive data (or all data).",
            "If you must support backup, keep allowBackup=\"true\" but exclude sensitive files: android:dataExtractionRules (API 31+, covers both cloud-backup and device-transfer) plus android:fullBackupContent (API 30 and lower) for legacy devices.",
            "Author the XML rule files under res/xml/ and reference them from the <application> tag; add xmlns:tools and tools:targetApi if you gate attributes by API level.",
            "Never rely on backup exclusion alone for secrets — encrypt at rest. Note Jetpack Security (androidx.security:security-crypto, EncryptedSharedPreferences/EncryptedFile) was deprecated in April 2025 (final release 1.1.0-alpha07); for new code prefer Jetpack DataStore for persistence with Google Tink for encryption and keys held in the Android Keystore.",
            "Rebuild the release and confirm the merged manifest reports allowBackup=\"false\" (or that the extraction rules exclude the sensitive files under both cloud-backup and device-transfer)."
        ],
        "code_example": "<!-- Preferred: disable backup entirely (blocks Google Drive / Auto Backup) -->\n<application\n    android:allowBackup=\"false\">\n    <!-- ... -->\n</application>\n\n<!-- NOTE: on some OEMs android:allowBackup=\"false\" does NOT stop device-to-device (D2D)\n     transfer. To also block D2D, exclude the data via dataExtractionRules below. -->\n\n<!-- Alternative: keep backup but exclude secrets from BOTH cloud backup and D2D -->\n<application\n    android:allowBackup=\"true\"\n    android:dataExtractionRules=\"@xml/data_extraction_rules\"\n    android:fullBackupContent=\"@xml/backup_rules\">\n</application>\n\n<!-- res/xml/data_extraction_rules.xml  (API 31+, Android 12+) -->\n<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<data-extraction-rules>\n    <cloud-backup>\n        <exclude domain=\"sharedpref\" path=\"auth_prefs.xml\"/>\n        <exclude domain=\"database\"  path=\"secrets.db\"/>\n        <exclude domain=\"file\"      path=\"keys/\"/>\n    </cloud-backup>\n    <device-transfer>\n        <exclude domain=\"sharedpref\" path=\"auth_prefs.xml\"/>\n        <exclude domain=\"database\"  path=\"secrets.db\"/>\n        <exclude domain=\"file\"      path=\"keys/\"/>\n    </device-transfer>\n</data-extraction-rules>\n\n<!-- res/xml/backup_rules.xml  (legacy, API 30 and lower) -->\n<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<full-backup-content>\n    <exclude domain=\"sharedpref\" path=\"auth_prefs.xml\"/>\n    <exclude domain=\"database\"  path=\"secrets.db\"/>\n</full-backup-content>",
        "how_to_verify": "Primary check: confirm the merged manifest shows android:allowBackup=\"false\" via `apkanalyzer manifest print app-release.apk` (inspect the <application> tag). Do NOT rely on `adb backup` as the test on current devices: for apps targeting API 31+ on Android 12+, adb backup excludes app data by default regardless of the flag, so an empty archive proves nothing. To actually observe the adb-backup vector you need a device on Android 11 or lower (or a temporarily debuggable build): `adb backup -noapk -f test.ab com.example.app`, then unpack with android-backup-extractor (abe) and confirm the excluded files are absent. For the selective/D2D case, verify the extraction-rules XML lists the sensitive files under both <cloud-backup> and <device-transfer>.",
        "references": [
            "https://developer.android.com/identity/data/autobackup",
            "https://developer.android.com/about/versions/12/behavior-changes-12",
            "https://cwe.mitre.org/data/definitions/530.html",
            "https://mas.owasp.org/MASVS/05-MASVS-STORAGE/"
        ]
    },
    "low-min-sdk": {
        "summary": "minSdkVersion is set to a very old API level, so the app can be installed on Android versions that no longer receive security patches and that lack the platform security features the app should be relying on.",
        "why_it_matters": "Old OS releases carry unpatched kernel, media-framework, TLS, and (on very old versions) non-updatable WebView vulnerabilities that the app cannot mitigate from user space. A low floor also means you cannot depend on modern defenses: declarative Network Security Config is only enforced from API 24 (Android 7.0), hardware-backed Android Keystore is available from API 23 (Android 6.0), and cleartext traffic is only disabled by default for apps targeting API 28+. Shipping to these devices exposes users to known, weaponized exploits (MASVS-PLATFORM).",
        "fix_steps": [
            "Pick a defensible floor. For new/maintained apps, minSdk 24 (Android 7.0) is a practical minimum; prefer 26 (Android 8.0) to reliably use Network Security Config, hardware-backed Keystore, and modern crypto libraries.",
            "Raise minSdk in the module build.gradle(.kts) defaultConfig.",
            "Add a res/xml/network_security_config.xml (enforced from API 24) to disable cleartext and, where appropriate, pin certificates; reference it from the manifest.",
            "If you drop very old devices, remove now-dead compat branches; if you keep Java 8+ APIs, enable core library desugaring instead of lowering the floor.",
            "Build and test on an emulator/device at exactly the new minSdk, then confirm the manifest's uses-sdk value."
        ],
        "code_example": "// app/build.gradle.kts\nandroid {\n    compileSdk = 35\n    defaultConfig {\n        minSdk = 26        // Android 8.0 — floor with modern security APIs\n        targetSdk = 35\n    }\n    compileOptions {\n        sourceCompatibility = JavaVersion.VERSION_17\n        targetCompatibility = JavaVersion.VERSION_17\n        isCoreLibraryDesugaringEnabled = true\n    }\n}\ndependencies {\n    coreLibraryDesugaring(\"com.android.tools:desugar_jdk_libs:2.1.5\")\n\n    // Secure storage: androidx.security:security-crypto (EncryptedSharedPreferences /\n    // EncryptedFile) was DEPRECATED in April 2025 (final release 1.1.0-alpha07) and will\n    // not receive further fixes. For new code prefer Jetpack DataStore + Google Tink,\n    // with keys protected by the Android Keystore (all usable once minSdk >= 23):\n    implementation(\"androidx.datastore:datastore-preferences:1.1.1\")\n    implementation(\"com.google.crypto.tink:tink-android:1.15.0\")\n}\n\n<!-- AndroidManifest.xml -->\n<application\n    android:networkSecurityConfig=\"@xml/network_security_config\">\n</application>\n\n<!-- res/xml/network_security_config.xml -->\n<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<network-security-config>\n    <base-config cleartextTrafficPermitted=\"false\"/>\n</network-security-config>",
        "how_to_verify": "Run `apkanalyzer manifest min-sdk app-release.apk` (or `aapt dump badging app-release.apk | grep sdkVersion`) and confirm the reported minSdkVersion matches the new floor. Install the release on a device at that API level and smoke-test; installs on lower levels should be rejected by the Play/PackageManager check.",
        "references": [
            "https://developer.android.com/guide/topics/manifest/uses-sdk-element",
            "https://developer.android.com/privacy-and-security/security-config",
            "https://developer.android.com/studio/write/java8-support#library-desugaring",
            "https://mas.owasp.org/MASVS/08-MASVS-PLATFORM/"
        ]
    },
    "outdated-target-sdk": {
        "summary": "targetSdkVersion is below the current Play Store / security-defaults threshold. A low target opts the app out of newer OS security and privacy defaults, and blocks Play Store submission/updates.",
        "why_it_matters": "targetSdk selects which OS compatibility behaviors apply. A low value keeps the app on legacy defaults: cleartext HTTP permitted by default (< API 28), no scoped-storage enforcement (< 29/30), lax PendingIntent mutability and implicit-intent handling, and no foreground-service-type enforcement. Google Play requires new apps and updates to target within one year of the latest Android release (API 34 for the 2024 window, API 35 for 2025), so an outdated target also means you cannot ship security fixes through Play. Missing these hardened defaults broadens the app's attack surface (MASVS-PLATFORM).",
        "fix_steps": [
            "Set compileSdk and targetSdk to 35 (Android 15) to meet the current Play requirement and adopt the latest secure defaults.",
            "Update Android Gradle Plugin and AndroidX/third-party dependencies to versions that compile against SDK 35.",
            "Work through the behavior changes for the intervening targets: confirm cleartext is off (or explicitly configured via Network Security Config), verify scoped-storage usage, make every PendingIntent explicitly FLAG_IMMUTABLE/FLAG_MUTABLE, and mark BroadcastReceivers RECEIVER_EXPORTED/NOT_EXPORTED (required at target 34+).",
            "For foreground services, declare a foregroundServiceType and the matching permission (mandatory when targeting 34+).",
            "Regression-test on Android 14/15 devices, then bump the target and re-run the Play pre-launch report."
        ],
        "code_example": "// app/build.gradle.kts\nandroid {\n    compileSdk = 35\n    defaultConfig {\n        minSdk = 26\n        targetSdk = 35     // Android 15 — meets Play target-API requirement\n    }\n}\n\n<!-- AndroidManifest.xml: foreground service type is required at target 34+ -->\n<uses-permission android:name=\"android.permission.FOREGROUND_SERVICE\"/>\n<uses-permission android:name=\"android.permission.FOREGROUND_SERVICE_DATA_SYNC\"/>\n\n<service\n    android:name=\".SyncService\"\n    android:foregroundServiceType=\"dataSync\"\n    android:exported=\"false\"/>\n\n// Kotlin: PendingIntents must set mutability at target 31+\nval pi = PendingIntent.getActivity(\n    context, 0, intent,\n    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE\n)",
        "how_to_verify": "Run `apkanalyzer manifest target-sdk app-release.apk` and confirm it returns 35. Upload the artifact to the Play Console — it must pass the target-API requirement gate — and review the pre-launch report for behavior-change warnings on Android 14/15.",
        "references": [
            "https://developer.android.com/google/play/requirements/target-sdk",
            "https://developer.android.com/about/versions/15/behavior-changes-15",
            "https://developer.android.com/about/versions/14/behavior-changes-14",
            "https://mas.owasp.org/MASVS/08-MASVS-PLATFORM/"
        ]
    },
    "webview-debugging": {
        "summary": "WebView.setWebContentsDebuggingEnabled(true) is called unconditionally, so it stays on in the release build. This exposes every WebView in the app to Chrome DevTools remote inspection over adb.",
        "why_it_matters": "When contents debugging is enabled, anyone with adb access to the device can open chrome://inspect on a connected machine and attach DevTools to the app's WebViews. They can read the live DOM, cookies, localStorage/sessionStorage, and injected @JavascriptInterface bridges, exfiltrate session and auth tokens, and drive the JS-to-native bridge to reach native functionality. It effectively turns any WebView into an open debugging port (CWE-489; MASVS-RESILIENCE / MASVS-CODE).",
        "fix_steps": [
            "Locate every call to WebView.setWebContentsDebuggingEnabled(...) in app and library init code.",
            "Never enable it unconditionally. Gate the call so it only runs in debuggable builds — check ApplicationInfo.FLAG_DEBUGGABLE (works even in library modules without BuildConfig) or BuildConfig.DEBUG.",
            "Remove any stray/always-on enablement that a dependency or debug tool may have added.",
            "Ensure release builds are non-debuggable (see android-debuggable) so the gate evaluates to false in production.",
            "Rebuild the signed release and confirm no WebView is inspectable."
        ],
        "code_example": "import android.content.pm.ApplicationInfo\nimport android.webkit.WebView\n\n// Enable WebView contents debugging ONLY in debuggable builds.\nfun configureWebViewDebugging(appContext: android.content.Context) {\n    val isDebuggable =\n        (appContext.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0\n    if (isDebuggable) {\n        WebView.setWebContentsDebuggingEnabled(true)\n    }\n}\n\n// Equivalent, if you have BuildConfig available in the module:\n// if (BuildConfig.DEBUG) {\n//     WebView.setWebContentsDebuggingEnabled(true)\n// }",
        "how_to_verify": "Install the release build, connect the device via adb, and open chrome://inspect#devices while navigating to a screen that hosts a WebView — no WebView should be listed. Statically, `grep -rn \"setWebContentsDebuggingEnabled\" src/` should show only debug-gated call sites. Confirm the release manifest is non-debuggable so the guard resolves to false.",
        "references": [
            "https://developer.android.com/reference/android/webkit/WebView#setWebContentsDebuggingEnabled(boolean)",
            "https://developer.android.com/develop/ui/views/layout/webapps/debugging-web-apps",
            "https://cwe.mitre.org/data/definitions/489.html",
            "https://mas.owasp.org/MASVS/09-MASVS-RESILIENCE/"
        ]
    },
    "exported-content-provider": {
        "summary": "A ContentProvider is exported (reachable by other installed apps) with no permission guard, so any app on the device can read or write its data through the content:// authority. If the provider builds SQL or resolves file paths from caller-supplied input, it is also open to SQL injection and path traversal.",
        "why_it_matters": "Any third-party app can query/insert/update/delete the provider's records without user consent, exposing databases, credentials, or PII. When selection/projection arguments are concatenated into SQL, an attacker crafts input like ' OR '1'='1 to dump other tables (CWE-89); when a custom openFile() concatenates the URI into a path, '../' segments read arbitrary app-private files. Providers in apps with targetSdk < 17 default to exported=true, so this is frequently unintentional.",
        "fix_steps": [
            "Decide whether other apps genuinely need this data. If not, set android:exported=\"false\" on the <provider>.",
            "If cross-app access is required, gate it behind a signature-level custom permission (or separate readPermission/writePermission) rather than leaving it open.",
            "Set android:grantUriPermissions=\"true\" and hand out temporary, per-URI access with Intent.FLAG_GRANT_READ_URI_PERMISSION instead of a blanket export.",
            "Never concatenate untrusted selection/projection into SQL: bind values with selectionArgs and whitelist columns via SQLiteQueryBuilder.setProjectionMap()/setStrict(true).",
            "For file sharing, replace any custom openFile() with androidx.core.content.FileProvider and an XML path config; canonicalize and validate any path you resolve.",
            "Rebuild and confirm the exported/permission state in the merged manifest."
        ],
        "code_example": "<!-- AndroidManifest.xml -->\n<!-- OPTION A (preferred): keep it private -->\n<provider\n    android:name=\".data.NotesProvider\"\n    android:authorities=\"com.example.app.notes\"\n    android:exported=\"false\" />\n\n<!-- OPTION B: must be shared with your other signed app -->\n<permission\n    android:name=\"com.example.app.permission.READ_NOTES\"\n    android:protectionLevel=\"signature\" />\n<provider\n    android:name=\".data.NotesProvider\"\n    android:authorities=\"com.example.app.notes\"\n    android:exported=\"true\"\n    android:readPermission=\"com.example.app.permission.READ_NOTES\"\n    android:grantUriPermissions=\"true\" />\n\n// NotesProvider.kt — injection-safe query\noverride fun query(\n    uri: Uri, projection: Array<String>?, selection: String?,\n    selectionArgs: Array<String>?, sortOrder: String?\n): Cursor {\n    val qb = SQLiteQueryBuilder().apply {\n        tables = \"notes\"\n        // Whitelist exposed columns to block projection injection\n        projectionMap = mapOf(\"_id\" to \"_id\", \"title\" to \"title\", \"body\" to \"body\")\n        isStrict = true // rejects malicious tokens in selection\n    }\n    val db = dbHelper.readableDatabase\n    // Values are bound, never concatenated into the SQL string\n    return qb.query(db, projection, selection, selectionArgs, null, null, sortOrder)\n}",
        "how_to_verify": "Run `apkanalyzer manifest print app.apk` (or unzip the APK and `aapt2 dump xmltree ... AndroidManifest.xml`) and confirm the <provider> shows android:exported=false or a signature permission. From a separate unsigned test app run contentResolver.query(Uri.parse(\"content://com.example.app.notes\"), ...) and confirm a SecurityException. Fuzz selection with `' OR '1'='1` and unexpected projection columns and confirm no extra rows/columns are returned; probe openFile with '../' paths and confirm access is denied.",
        "references": [
            "https://developer.android.com/guide/topics/manifest/provider-element",
            "https://developer.android.com/privacy-and-security/security-tips#content-providers",
            "https://cwe.mitre.org/data/definitions/926.html",
            "https://cwe.mitre.org/data/definitions/89.html"
        ]
    },
    "exported-component-no-permission": {
        "summary": "An Activity, Service, or BroadcastReceiver is exported (android:exported=\"true\", or implicitly exported via an intent-filter) with no android:permission guard, so any app can launch it, bind to it, or deliver intents to it.",
        "why_it_matters": "Exported components are a direct IPC attack surface. A malicious app can start an exported Activity to bypass a login/lock screen or spoof UI, bind to an exported Service to invoke privileged operations, or fire crafted broadcasts at an exported Receiver. If the component trusts intent extras — a redirect URL, a file path, an isAdmin flag — this enables intent redirection, privilege escalation, and data theft, all without any user interaction.",
        "fix_steps": [
            "Enumerate every exported component and decide whether external callers are actually needed. If not, set android:exported=\"false\".",
            "If it must stay exported, protect it with android:permission at signature protectionLevel (or an appropriate platform permission the caller already holds).",
            "Treat all incoming Intent action/data/extras as untrusted: validate and whitelist them; never trust caller-supplied paths, URLs, or authorization flags.",
            "For a bound Service, add a defense-in-depth caller check inside the IPC/AIDL methods (where the binder identity is valid) using Binder.getCallingUid() or checkCallingPermission(); note this does NOT work in a started Service's onStartCommand — there the manifest android:permission is the actual guard because no binder transaction is in progress.",
            "Remove intent-filters the component does not need (an intent-filter makes a component exported unless you explicitly set exported=false).",
            "Rebuild and inspect the merged manifest to confirm each component is locked down."
        ],
        "code_example": "<!-- Internal screen: no external access -->\n<activity\n    android:name=\".SettingsActivity\"\n    android:exported=\"false\" />\n\n<!-- Must be callable only by your other same-key app -->\n<permission\n    android:name=\"com.example.app.permission.CONTROL\"\n    android:protectionLevel=\"signature\" />\n<service\n    android:name=\".SyncService\"\n    android:exported=\"true\"\n    android:permission=\"com.example.app.permission.CONTROL\" />\n\n// SyncService.kt — the android:permission above is what actually blocks\n// unauthorized callers at start time. onStartCommand runs OUTSIDE any binder\n// transaction, so the caller identity is not available here\n// (checkCallingOrSelfPermission would silently fall back to a self-check);\n// just validate the still-untrusted intent extras.\noverride fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {\n    val action = intent?.getStringExtra(\"action\")\n    if (action !in setOf(\"push\", \"pull\")) {\n        stopSelf()\n        return START_NOT_STICKY\n    }\n    // ... handle validated action ...\n    return START_NOT_STICKY\n}",
        "how_to_verify": "Run `apkanalyzer manifest print app.apk` and confirm each component shows exported=false or an android:permission. Try to launch it externally: `adb shell am start -n com.example.app/.SettingsActivity` and `adb shell am start-service ...` should return a Permission Denial / SecurityException. From an unsigned test app, attempt startActivity/bindService/sendBroadcast and confirm access is refused. Re-run the platform scan to confirm the finding clears.",
        "references": [
            "https://developer.android.com/guide/topics/manifest/activity-element#exported",
            "https://developer.android.com/privacy-and-security/security-tips#use-permissions",
            "https://mas.owasp.org/MASVS/05-MASVS-PLATFORM/",
            "https://cwe.mitre.org/data/definitions/926.html"
        ]
    },
    "implicit-exported-component": {
        "summary": "A component declares an <intent-filter> but does not set android:exported explicitly. On Android 12 (API 31) and above this is required — apps targeting API 31+ that omit it fail to install — and relying on the implicit default silently exposes the component to other apps.",
        "why_it_matters": "A component that has an intent-filter defaults to exported=true when the attribute is absent, so a forgotten android:exported historically opened Activities, Services, and Receivers to any app unintentionally. Starting with targetSdk 31, the manifest merger hard-fails (\"must explicitly specify android:exported\") so the app will not install on Android 12+ devices. Making the value explicit both fixes the build break and forces a deliberate exposure decision for every IPC endpoint.",
        "fix_steps": [
            "Find every activity/service/receiver that contains an <intent-filter>, including the MAIN/LAUNCHER activity and manifest-registered receivers.",
            "Add android:exported explicitly to each one. Use true only when the component must respond to other apps (launcher, deep links, share/VIEW targets); otherwise false.",
            "Keep android:exported=\"true\" on the LAUNCHER activity — it must be reachable by the system.",
            "For receivers that only handle your own or protected system broadcasts, set exported=\"false\", or register them at runtime with ContextCompat.RECEIVER_NOT_EXPORTED (required on Android 13+).",
            "Raise compileSdk/targetSdk to 34/35 and rebuild to confirm the manifest merge no longer errors and lint is clean."
        ],
        "code_example": "<!-- Launcher: exported is required to be true -->\n<activity\n    android:name=\".MainActivity\"\n    android:exported=\"true\">\n    <intent-filter>\n        <action android:name=\"android.intent.action.MAIN\" />\n        <category android:name=\"android.intent.category.LAUNCHER\" />\n    </intent-filter>\n</activity>\n\n<!-- Reacts only to your own broadcast: not exported -->\n<receiver\n    android:name=\".InternalReceiver\"\n    android:exported=\"false\">\n    <intent-filter>\n        <action android:name=\"com.example.app.ACTION_REFRESH\" />\n    </intent-filter>\n</receiver>\n\n// Runtime registration (Android 13+ requires an export flag)\nval filter = IntentFilter(\"com.example.app.ACTION_REFRESH\")\nContextCompat.registerReceiver(\n    context, receiver, filter,\n    ContextCompat.RECEIVER_NOT_EXPORTED\n)",
        "how_to_verify": "Set targetSdk to 34/35 and build: a missing android:exported now fails the manifest merge with \"must explicitly specify android:exported\". Run `apkanalyzer manifest print app.apk` and confirm every component that has an intent-filter carries an explicit exported value. Run Android Lint and confirm the IntentFilterExportedReceiver / related checks pass. Install on an Android 12+ device/emulator to confirm no install error.",
        "references": [
            "https://developer.android.com/about/versions/12/behavior-changes-12#exported",
            "https://developer.android.com/guide/topics/manifest/activity-element#exported",
            "https://developer.android.com/develop/background-work/background-tasks/broadcasts#context-registered-receivers",
            "https://cwe.mitre.org/data/definitions/926.html"
        ]
    },
    "high-risk-permissions": {
        "summary": "The app requests one or more special/high-risk permissions (e.g. SYSTEM_ALERT_WINDOW, QUERY_ALL_PACKAGES, REQUEST_INSTALL_PACKAGES) that grant broad, sensitive capabilities and are restricted by Google Play. Each must be justified with a scoped alternative or removed.",
        "why_it_matters": "SYSTEM_ALERT_WINDOW lets the app draw over other apps, enabling tapjacking/overlay phishing that steals taps and credentials. QUERY_ALL_PACKAGES reveals the full list of installed apps — a privacy/fingerprinting signal — and needs an approved Play Console declaration. REQUEST_INSTALL_PACKAGES lets the app trigger APK installs, a classic sideloading/malware dropper vector. Google Play restricts all of these and can reject or remove apps that keep them without an approved, in-policy use case.",
        "fix_steps": [
            "Inspect the merged manifest and identify which module or third-party library pulls in each high-risk permission.",
            "Remove any you do not need; strip transitively-added ones with tools:node=\"remove\".",
            "Replace with scoped APIs: use a <queries> block instead of QUERY_ALL_PACKAGES; use PackageInstaller sessions with explicit user consent instead of blanket install rights.",
            "For SYSTEM_ALERT_WINDOW, only keep it if genuinely needed, gate it at runtime with Settings.canDrawOverlays(), and prefer bubbles/notifications where possible.",
            "For each special permission, check the specific grant at runtime (canDrawOverlays / packageManager.canRequestPackageInstalls()).",
            "File the required Sensitive/Restricted permission declaration in Play Console for anything you retain."
        ],
        "code_example": "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\"\n          xmlns:tools=\"http://schemas.android.com/tools\">\n\n    <!-- Drop a permission a dependency added transitively -->\n    <uses-permission android:name=\"android.permission.QUERY_ALL_PACKAGES\"\n        tools:node=\"remove\" />\n\n    <!-- Declare only the specific apps/intents you must see -->\n    <queries>\n        <package android:name=\"com.google.android.apps.maps\" />\n        <intent>\n            <action android:name=\"android.intent.action.SEND\" />\n            <data android:mimeType=\"image/*\" />\n        </intent>\n    </queries>\n</manifest>\n\n// Overlay: request the special grant explicitly, only when needed\nif (!Settings.canDrawOverlays(this)) {\n    overlayLauncher.launch(\n        Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,\n               Uri.parse(\"package:$packageName\"))\n    )\n}\n\n// Install: check the scoped grant instead of assuming it\nif (packageManager.canRequestPackageInstalls()) { startInstallSession() }",
        "how_to_verify": "Run `apkanalyzer manifest print app.apk` (or inspect build/intermediates/merged_manifests/.../AndroidManifest.xml) and confirm the high-risk permissions are removed or replaced. Confirm app-list features still work through <queries>. On a device, `adb shell dumpsys package com.example.app | findstr permission` shows the reduced set; Settings.canDrawOverlays returns false until the user grants it. For anything retained, confirm an approved Play Console declaration exists.",
        "references": [
            "https://developer.android.com/training/package-visibility",
            "https://support.google.com/googleplay/android-developer/answer/10158779",
            "https://developer.android.com/reference/android/Manifest.permission#SYSTEM_ALERT_WINDOW",
            "https://cwe.mitre.org/data/definitions/250.html"
        ]
    },
    "dangerous-permissions": {
        "summary": "The app requests runtime (dangerous) permissions such as location, contacts, camera, microphone, SMS, or media/storage. Each should pass a least-privilege review: justified by a real feature, requested at runtime with rationale, and replaced by a permission-free API where one exists.",
        "why_it_matters": "Dangerous permissions grant access to sensitive user data and hardware; over-requesting widens the attack surface and the blast radius if the app is ever compromised, erodes user trust, and drives runtime denials. Some groups (SMS, Call Log) are heavily restricted by Google Play and cause rejection when requested without an approved default-handler use case. On Android 6+ these must be granted at runtime, so requesting them out of context leads to hard denials and broken flows.",
        "fix_steps": [
            "List every dangerous permission and map each to a concrete feature; remove any with no clear justification.",
            "Prefer no-permission alternatives: the Photo Picker (PickVisualMedia) instead of READ_MEDIA_*/READ_EXTERNAL_STORAGE, the Storage Access Framework for documents, ACTION_INSERT for adding contacts, and COARSE location where FINE is not required.",
            "Request remaining permissions at runtime, in context, using the Activity Result APIs and shouldShowRequestPermissionRationale() to explain why.",
            "Use granular, version-scoped permissions: on Android 13+ request READ_MEDIA_IMAGES/VIDEO/AUDIO instead of broad storage, and support the Android 14 partial grant READ_MEDIA_VISUAL_USER_SELECTED (declare it in the manifest so it is grantable).",
            "Handle denial gracefully — degrade the feature instead of blocking the whole app.",
            "Confirm the trimmed, version-scoped permission set in the merged manifest."
        ],
        "code_example": "<!-- Version-scope legacy storage, use granular media on 13+ -->\n<uses-permission android:name=\"android.permission.READ_EXTERNAL_STORAGE\"\n    android:maxSdkVersion=\"32\" />\n<uses-permission android:name=\"android.permission.READ_MEDIA_IMAGES\" />\n<!-- Android 14 partial access: must be declared to be grantable at runtime -->\n<uses-permission android:name=\"android.permission.READ_MEDIA_VISUAL_USER_SELECTED\" />\n\n// Best: no permission at all — system Photo Picker\nprivate val pickMedia = registerForActivityResult(\n    ActivityResultContracts.PickVisualMedia()\n) { uri -> uri?.let { handleImage(it) } }\n\nfun choose() = pickMedia.launch(\n    PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly)\n)\n\n// When a runtime permission is truly needed, request in context\nprivate val requestPerms = registerForActivityResult(\n    ActivityResultContracts.RequestMultiplePermissions()\n) { grants -> if (grants.values.any { it }) loadPhotos() else degradeGracefully() }\n\nfun needMedia() {\n    val perms = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)\n        arrayOf(Manifest.permission.READ_MEDIA_IMAGES,\n                Manifest.permission.READ_MEDIA_VISUAL_USER_SELECTED) // Android 14 partial access\n    else arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE)\n    requestPerms.launch(perms)\n}",
        "how_to_verify": "Run `apkanalyzer manifest print app.apk` and confirm only justified, version-scoped permissions remain. On a device, `adb shell dumpsys package com.example.app | findstr permission` shows the granted set. Manually deny each permission and confirm the app degrades instead of crashing. Confirm the Photo Picker flow returns a usable URI while `dumpsys` shows no media permission granted. Ensure no SMS/Call Log permissions remain unless the app is a default handler with an approved declaration.",
        "references": [
            "https://developer.android.com/training/permissions/requesting",
            "https://developer.android.com/training/data-storage/shared/photopicker",
            "https://mas.owasp.org/MASVS/05-MASVS-PLATFORM/",
            "https://cwe.mitre.org/data/definitions/250.html"
        ]
    },
    "weak-custom-permission": {
        "summary": "The app defines a custom permission that guards its components but declares it at protectionLevel=\"normal\" (or \"dangerous\") instead of \"signature\". A normal permission is auto-granted to any app that requests it, so the guard provides no real protection.",
        "why_it_matters": "A \"normal\" custom permission is granted automatically to any app that lists it in <uses-permission>, and \"dangerous\" can be granted by the user — neither restricts access to apps you control, so a malicious app simply requests your permission and reaches the components you believed were protected. There is also a permission-definition race: if an attacker's app is installed first and defines a permission with the same name at a weaker level, that weaker definition can win. Setting protectionLevel=\"signature\" grants the permission only to apps signed with your key, closing both holes.",
        "fix_steps": [
            "Change each custom permission that guards internal or intra-suite components to android:protectionLevel=\"signature\".",
            "Ensure every app that should share access is signed with the same key (or key set / rotated key lineage).",
            "Use a reverse-DNS, app-specific permission name (com.yourco.app.permission.X) to reduce name collisions and first-definer attacks.",
            "Confirm the guarded components actually reference the permission via android:permission / readPermission / writePermission.",
            "Rebuild and re-sign all cooperating apps with the shared signing config, then verify the grant only lands on same-key apps."
        ],
        "code_example": "<!-- Define with signature-level protection -->\n<permission\n    android:name=\"com.example.app.permission.SYNC_DATA\"\n    android:protectionLevel=\"signature\"\n    android:label=\"@string/perm_sync_label\"\n    android:description=\"@string/perm_sync_desc\" />\n\n<!-- Guard the component -->\n<service\n    android:name=\".SyncService\"\n    android:exported=\"true\"\n    android:permission=\"com.example.app.permission.SYNC_DATA\" />\n\n<!-- The cooperating (same-key) app requests it -->\n<uses-permission android:name=\"com.example.app.permission.SYNC_DATA\" />\n\n// build.gradle — both apps must share ONE signing config\nandroid {\n    signingConfigs {\n        release {\n            storeFile file(\"../shared-release.jks\")\n            storePassword System.getenv(\"KS_PASS\")\n            keyAlias \"shared\"\n            keyPassword System.getenv(\"KEY_PASS\")\n        }\n    }\n    buildTypes { release { signingConfig signingConfigs.release } }\n}",
        "how_to_verify": "Run `apkanalyzer manifest print app.apk` and confirm the <permission> shows protectionLevel=\"signature\" (0x2). Build a differently-signed test app that requests the permission: `adb shell dumpsys package com.example.testapp | findstr SYNC_DATA` shows it not granted and calls into the guarded component fail with SecurityException, while your same-key app still gets access. Confirm both production APKs share one signer with `apksigner verify --print-certs app1.apk` and compare against app2.apk.",
        "references": [
            "https://developer.android.com/guide/topics/manifest/permission-element#plevel",
            "https://developer.android.com/guide/topics/permissions/defining",
            "https://cwe.mitre.org/data/definitions/732.html",
            "https://mas.owasp.org/MASVS/05-MASVS-PLATFORM/"
        ]
    },
    "cleartext-traffic-enabled": {
        "summary": "Your manifest sets android:usesCleartextTraffic=\"true\", which explicitly re-enables unencrypted HTTP, FTP, and WebSocket (ws://) traffic app-wide. This overrides the secure-by-default behavior that Android 9 (API 28) and later apply.",
        "why_it_matters": "Cleartext traffic travels the network unencrypted, so anyone on the path — a malicious Wi-Fi hotspot, a compromised router, or an ISP-level attacker — can read every request and response, harvest session tokens, PII, and API keys, and silently modify payloads (man-in-the-middle). Because the flag is global, a single legacy endpoint forces the whole app to permit HTTP, expanding the attack surface far beyond the one host you intended. This maps to CWE-319 (Cleartext Transmission of Sensitive Information).",
        "fix_steps": [
            "Remove android:usesCleartextTraffic=\"true\" from the <application> element (or set it to \"false\").",
            "Migrate every endpoint the app talks to from http:// to https:// and confirm each server presents a valid, publicly-trusted TLS certificate.",
            "Add a Network Security Configuration file that hard-fails cleartext globally so a future regression cannot silently re-enable it.",
            "If a small number of hosts genuinely still require HTTP (e.g. a legacy internal server), scope the exception to those exact domains in a <domain-config> instead of the global flag, and track their HTTPS migration.",
            "Rebuild, then confirm the merged manifest no longer contains a global cleartext permission."
        ],
        "code_example": "<!-- AndroidManifest.xml -->\n<application\n    android:name=\".MyApp\"\n    android:networkSecurityConfig=\"@xml/network_security_config\">\n    <!-- android:usesCleartextTraffic REMOVED (defaults to false on targetSdk >= 28) -->\n</application>\n\n<!-- res/xml/network_security_config.xml -->\n<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<network-security-config>\n    <!-- Deny cleartext everywhere -->\n    <base-config cleartextTrafficPermitted=\"false\" />\n\n    <!-- OPTIONAL: narrowly permit HTTP for one legacy host only, if unavoidable -->\n    <domain-config cleartextTrafficPermitted=\"true\">\n        <domain includeSubdomains=\"false\">legacy-internal.example.com</domain>\n    </domain-config>\n</network-security-config>",
        "how_to_verify": "Inspect the merged manifest with `apkanalyzer manifest print app-release.apk` (or `./gradlew :app:processReleaseManifest` and open app/build/intermediates/merged_manifests/.../AndroidManifest.xml) and confirm usesCleartextTraffic is absent or \"false\". At runtime, call `NetworkSecurityPolicy.getInstance().isCleartextTrafficPermitted(\"api.example.com\")` — it must return false for hosts that should be HTTPS-only. Finally, route the device through an intercepting proxy (mitmproxy/Burp) without installing its CA: any remaining HTTP call will now fail instead of succeeding in cleartext.",
        "references": [
            "https://developer.android.com/privacy-and-security/security-config",
            "https://developer.android.com/topic/security/best-practices",
            "https://cwe.mitre.org/data/definitions/319.html",
            "https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0021/"
        ]
    },
    "cleartext-traffic-default": {
        "summary": "Your app targets an SDK below API 28 (Android 9). On those older targets the platform default for android:usesCleartextTraffic is TRUE, so the app permits unencrypted HTTP even though the manifest never asks for it. The finding reflects an implicit permission, not an explicit flag.",
        "why_it_matters": "Because cleartext is allowed by default, any accidental http:// URL, redirect, or third-party SDK call will transmit in the clear and be exposed to man-in-the-middle interception and tampering (CWE-319). Shipping with an old targetSdkVersion also blocks you from newer platform hardening and, independently, violates Google Play's target-API requirements, which will eventually prevent updates from being published. The safe path is to raise the target and lock cleartext down explicitly.",
        "fix_steps": [
            "Raise targetSdkVersion (and compileSdk) to 35 (Android 15) — or at minimum 34 (Android 14) — in your module build.gradle. On API 28+ cleartext defaults to disabled.",
            "Test the app against the new target for behavior changes (scoped storage, foreground-service types, permission prompts, etc.) that come with the bump.",
            "Add an explicit Network Security Configuration with cleartextTrafficPermitted=\"false\" so the posture is enforced regardless of target level and cannot silently regress.",
            "Do NOT paper over the old target by only adding android:usesCleartextTraffic=\"false\" — raising the target is required for Play compliance and platform hardening.",
            "Reassemble and verify the effective cleartext policy at runtime."
        ],
        "code_example": "// app/build.gradle.kts\nandroid {\n    compileSdk = 35\n\n    defaultConfig {\n        minSdk = 24\n        targetSdk = 35            // >= 28 makes cleartext default to DISABLED\n    }\n}\n\n// AndroidManifest.xml\n<application\n    android:networkSecurityConfig=\"@xml/network_security_config\">\n</application>\n\n<!-- res/xml/network_security_config.xml -->\n<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<network-security-config>\n    <base-config cleartextTrafficPermitted=\"false\" />\n</network-security-config>",
        "how_to_verify": "Confirm the compiled target with `apkanalyzer manifest target-sdk-version app-release.apk` or `aapt2 dump badging app-release.apk | grep targetSdkVersion` — it must report your new target (35, or at least 34). Note: `apkanalyzer apk summary` only prints application id / version code / version name, NOT the SDK level, so use the `manifest target-sdk-version` verb. At runtime, `NetworkSecurityPolicy.getInstance().isCleartextTrafficPermitted()` should return false. Attempt an http:// request from the app and confirm it throws (e.g. `java.io.IOException: Cleartext HTTP traffic to ... not permitted`) rather than completing.",
        "references": [
            "https://developer.android.com/privacy-and-security/security-config",
            "https://developer.android.com/google/play/requirements/target-sdk",
            "https://developer.android.com/reference/android/security/NetworkSecurityPolicy#isCleartextTrafficPermitted()",
            "https://cwe.mitre.org/data/definitions/319.html"
        ]
    },
    "no-network-security-config": {
        "summary": "Your app does not declare a Network Security Configuration (no android:networkSecurityConfig attribute pointing at an res/xml resource). Without one you rely entirely on platform defaults and cannot centrally control cleartext policy, trust anchors, certificate pinning, or debug-only CA overrides.",
        "why_it_matters": "A missing config means there is no single, auditable place that enforces your TLS posture. You lose declarative certificate pinning, you cannot cleanly restrict which CAs are trusted per-domain, and — most dangerously — developers tend to work around the gap with insecure custom TrustManagers or a global usesCleartextTraffic flag. It also means a device that trusts an attacker-installed or user-added CA can MitM your traffic, because by default apps targeting API 24+ do not trust user-added CAs, but that guarantee is only meaningful when your config makes trust explicit. Establishing an NSC is the foundation for CWE-295 (improper certificate validation) and CWE-319 defenses.",
        "fix_steps": [
            "Create res/xml/network_security_config.xml.",
            "In <base-config>, set cleartextTrafficPermitted=\"false\" and pin trust to the system CA store only (exclude user-added CAs for production).",
            "Reference the file from the <application> element via android:networkSecurityConfig.",
            "For engineers who need to proxy traffic, add a separate <debug-overrides> block that trusts a user CA — this block is ignored unless android:debuggable=\"true\", so it never ships in release.",
            "Optionally add <domain-config> blocks with a <pin-set> to pin your first-party API domains.",
            "Rebuild and confirm the config is applied."
        ],
        "code_example": "<!-- AndroidManifest.xml -->\n<application\n    android:networkSecurityConfig=\"@xml/network_security_config\">\n</application>\n\n<!-- res/xml/network_security_config.xml -->\n<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<network-security-config>\n    <base-config cleartextTrafficPermitted=\"false\">\n        <trust-anchors>\n            <!-- Production trusts only the system CA store, not user-added CAs -->\n            <certificates src=\"system\" />\n        </trust-anchors>\n    </base-config>\n\n    <domain-config>\n        <domain includeSubdomains=\"true\">api.example.com</domain>\n        <pin-set expiration=\"2026-12-31\">\n            <!-- SHA-256 of the SubjectPublicKeyInfo; include a backup pin -->\n            <pin digest=\"SHA-256\">7HIpactkIAq2Y49orFOOQKurWxmmSFZhBCoQYcRhJ3Y=</pin>\n            <pin digest=\"SHA-256\">fwza0LRMXouZHRC8Ei+4PyuldPDcf3UKgO/04cDM1oE=</pin>\n        </pin-set>\n    </domain-config>\n\n    <!-- Only applied on debuggable builds; stripped from release -->\n    <debug-overrides>\n        <trust-anchors>\n            <certificates src=\"user\" />\n            <certificates src=\"system\" />\n        </trust-anchors>\n    </debug-overrides>\n</network-security-config>",
        "how_to_verify": "After building, confirm the release manifest contains android:networkSecurityConfig and the res/xml file is packaged (`unzip -l app-release.apk | grep network_security_config`). Install the release build and run traffic through Burp/mitmproxy with its CA added to the user store — pinned/first-party HTTPS calls must fail (proving user CAs are not trusted and pins hold). Then install the debug build and repeat: interception should now succeed, proving <debug-overrides> is active only in debuggable builds. Generate real pins with `openssl s_client -connect api.example.com:443 | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64`.",
        "references": [
            "https://developer.android.com/privacy-and-security/security-config",
            "https://developer.android.com/privacy-and-security/security-ssl",
            "https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0022/",
            "https://cwe.mitre.org/data/definitions/295.html"
        ]
    },
    "cleartext-url-in-code": {
        "summary": "The static analyzer found string literals beginning with http:// (rather than https://) embedded in your compiled DEX bytecode. These are hard-coded endpoints or resource URLs the app may contact over unencrypted HTTP at runtime.",
        "why_it_matters": "Even with a hardened manifest, an http:// literal that resolves to a cleartext-permitted host — or a redirect that downgrades HTTPS to HTTP — sends data in the clear and is trivially intercepted and tampered with on hostile networks (CWE-319). Attackers can also exploit these fixed URLs for man-in-the-middle content injection (e.g. serving a malicious update or ad payload). Because the URLs are compiled in, they cannot be rotated server-side, so any weak endpoint is a permanent liability until the binary is rebuilt.",
        "fix_steps": [
            "Locate every offending literal — decompile and grep the DEX, or search the source tree, for \"http://\".",
            "Replace each with https:// and verify the target host serves valid TLS; if a dependency or SDK hardcodes HTTP, upgrade it or replace it.",
            "Centralize base URLs in one place (BuildConfig field or a constants object) so they cannot drift, and never store secrets in these literals.",
            "Enforce the rule at the platform level with a Network Security Configuration that forbids cleartext, so any missed http:// call fails loudly during testing instead of leaking silently.",
            "For Retrofit/OkHttp, add an interceptor (debug builds) that throws on any non-HTTPS request to catch regressions early.",
            "Rebuild with R8/minification and re-scan the DEX to confirm no cleartext literals remain in reachable code."
        ],
        "code_example": "// Before (compiled into DEX):\n// val BASE_URL = \"http://api.example.com/v1/\"\n\n// After: single source of truth, HTTPS only\nobject Endpoints {\n    const val BASE_URL = \"https://api.example.com/v1/\"\n}\n\n// Fail fast on any accidental cleartext request (add to debug OkHttpClient)\nval client = OkHttpClient.Builder()\n    .addInterceptor { chain ->\n        val request = chain.request()\n        require(request.url.isHttps) {\n            \"Blocked non-HTTPS request to ${request.url}\"\n        }\n        chain.proceed(request)\n    }\n    .build()\n\nval retrofit = Retrofit.Builder()\n    .baseUrl(Endpoints.BASE_URL)\n    .client(client)\n    .build()\n\n// Backed by a manifest-referenced res/xml/network_security_config.xml:\n// <base-config cleartextTrafficPermitted=\"false\" />",
        "how_to_verify": "Re-run the static scan, or manually: `apktool d app-release.apk` then `grep -rEi 'http://[a-z0-9.-]+' smali/` — there should be no cleartext literals in reachable code (test/analytics stub strings inside unused library code are lower risk but should still be reviewed). Dynamically, run the app end-to-end through mitmproxy without trusting its CA and confirm no plaintext HTTP flows appear and no requests silently downgrade. With cleartextTrafficPermitted=\"false\" set, any surviving http:// call will surface as an IOException in logcat.",
        "references": [
            "https://developer.android.com/privacy-and-security/risks/cleartext-communications",
            "https://developer.android.com/privacy-and-security/security-config",
            "https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0021/",
            "https://cwe.mitre.org/data/definitions/319.html"
        ]
    },
    "insecure-tls-validation": {
        "summary": "The app installs a custom X509TrustManager, SSLSocketFactory, or HostnameVerifier that disables or weakens TLS validation — for example a trust manager whose checkServerTrusted() does nothing, or a hostname verifier that returns true for every host. This makes encrypted connections trust any certificate.",
        "why_it_matters": "A trust-all TrustManager or an always-true HostnameVerifier defeats the entire purpose of TLS: the client no longer verifies it is talking to the real server, so any attacker who can present a self-signed or mismatched certificate (on public Wi-Fi, via DNS spoofing, or a rogue proxy) completes a successful man-in-the-middle attack and reads/modifies all traffic while the connection still looks encrypted. This is CWE-295 (Improper Certificate Validation), with CWE-297 (host mismatch) and CWE-296 (chain-of-trust) variants, and is one of the most exploited Android network flaws. It is almost always introduced as a shortcut to accept self-signed dev certs and then accidentally shipped to production.",
        "fix_steps": [
            "Delete all custom trust-all TrustManager, empty checkServerTrusted(), NullHostnameVerifier, and setHostnameVerifier { _, _ -> true } code. Never ship these.",
            "Use platform defaults: an ordinary HttpsURLConnection or a default OkHttpClient already performs full chain and hostname validation against the system trust store.",
            "If you need to trust a private/self-signed CA (internal servers), do it declaratively via a Network Security Configuration <trust-anchors> with a bundled CA certificate — not by disabling validation in code.",
            "For high-value first-party APIs, add certificate/public-key pinning via OkHttp CertificatePinner or an NSC <pin-set>, and always include a backup pin plus an expiration.",
            "For development-only proxy interception, restrict any relaxed trust to <debug-overrides> so it is stripped from release builds.",
            "Rebuild and confirm connections to a server with an invalid/mismatched certificate now fail."
        ],
        "code_example": "// REMOVE anything like this — it disables all validation:\n//   object : X509TrustManager {\n//       override fun checkServerTrusted(c: Array<X509Certificate>, t: String) {}\n//       ...\n//   }\n//   HttpsURLConnection.setDefaultHostnameVerifier { _, _ -> true }\n\n// DO: default validation + pinning for your API (OkHttp)\nval certificatePinner = CertificatePinner.Builder()\n    // sha256/ of the SubjectPublicKeyInfo; keep a backup pin\n    .add(\"api.example.com\", \"sha256/7HIpactkIAq2Y49orFOOQKurWxmmSFZhBCoQYcRhJ3Y=\")\n    .add(\"api.example.com\", \"sha256/fwza0LRMXouZHRC8Ei+4PyuldPDcf3UKgO/04cDM1oE=\")\n    .build()\n\nval client = OkHttpClient.Builder()\n    .certificatePinner(certificatePinner)   // no custom trust manager, no hostname verifier override\n    .build()\n\n/* To trust a PRIVATE CA, do it declaratively instead of in code:\n   res/xml/network_security_config.xml\n   <network-security-config>\n     <domain-config>\n       <domain includeSubdomains=\"true\">internal.example.com</domain>\n       <trust-anchors>\n         <certificates src=\"@raw/my_private_ca\" />\n       </trust-anchors>\n     </domain-config>\n   </network-security-config>\n*/",
        "how_to_verify": "Grep the source/DEX for the tell-tale patterns: `grep -rEn 'checkServerTrusted|ALLOW_ALL_HOSTNAME|HostnameVerifier|TrustManager|SSLSocketFactory' src/` and confirm no method body is empty or returns true unconditionally. Dynamically, point the app at a host presenting an untrusted or wrong-hostname certificate (or run mitmproxy without adding its CA to the trust store): the connection MUST fail with SSLHandshakeException/SSLPeerUnverifiedException. Then test pinning by rotating to a cert whose key is not pinned — it must also fail. Google Play's pre-launch report and static scanners flag residual trust-all managers, so re-scan after the fix.",
        "references": [
            "https://developer.android.com/privacy-and-security/security-ssl",
            "https://developer.android.com/privacy-and-security/risks/unsafe-trustmanager",
            "https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0023/",
            "https://cwe.mitre.org/data/definitions/295.html"
        ]
    },
    "unsigned-apk": {
        "summary": "The APK carries no valid signature — none of the v1 (JAR), v2, v3, or v4 signature schemes were found. Android cannot install it and there is no cryptographic proof of who built it or that its contents are intact.",
        "why_it_matters": "Every Android package must be signed; the platform's PackageManager rejects an unsigned APK at install time and refuses any later update whose signer does not match. Beyond installability, the signature is the sole integrity and authenticity guarantee for the app: without it, a repackaged or malware-injected build is indistinguishable from yours, and there is no signer identity to anchor update trust, signature-level permissions, or Play App Signing. This maps to CWE-347 (Improper Verification of Cryptographic Signature) and violates MASVS-RESILIENCE-3.",
        "fix_steps": [
            "Generate a private release keystore with a strong key (RSA-3072 or EC P-256 and a SHA-256 certificate signature) using keytool, and store it outside version control.",
            "Create a keystore.properties file (git-ignored) holding storeFile/storePassword/keyAlias/keyPassword, and load it in your module's build.gradle.kts.",
            "Add a 'release' signingConfig that references those credentials and enables the v2/v3 (and v4) schemes, then attach it to the release buildType.",
            "Build the release artifact with ./gradlew bundleRelease (AAB for Play) or assembleRelease; for a raw APK pipeline, zipalign first, then sign with apksigner.",
            "Enroll the app in Play App Signing so Google holds the app signing key and your keystore acts as the upload key.",
            "Run apksigner verify --verbose --print-certs to confirm the schemes are present and the signer is your key."
        ],
        "code_example": "# 1) Create a release keystore (one time)\nkeytool -genkeypair -v \\\n  -keystore release.jks \\\n  -alias upload \\\n  -keyalg RSA -keysize 3072 \\\n  -sigalg SHA256withRSA \\\n  -validity 10000 \\\n  -storetype PKCS12\n\n# 2) app/build.gradle.kts\nimport java.io.FileInputStream\nimport java.util.Properties\n\nval keystoreProps = Properties().apply {\n    val f = rootProject.file(\"keystore.properties\")\n    if (f.exists()) load(FileInputStream(f))\n}\n\nandroid {\n    signingConfigs {\n        create(\"release\") {\n            storeFile = file(keystoreProps.getProperty(\"storeFile\"))\n            storePassword = keystoreProps.getProperty(\"storePassword\")\n            keyAlias = keystoreProps.getProperty(\"keyAlias\")\n            keyPassword = keystoreProps.getProperty(\"keyPassword\")\n            enableV1Signing = false   // safe when minSdk >= 24 (Android 7.0)\n            enableV2Signing = true\n            enableV3Signing = true\n            enableV4Signing = true    // enables fast incremental install on Android 11+\n        }\n    }\n    buildTypes {\n        getByName(\"release\") {\n            signingConfig = signingConfigs.getByName(\"release\")\n            isMinifyEnabled = true\n            proguardFiles(\n                getDefaultProguardFile(\"proguard-android-optimize.txt\"),\n                \"proguard-rules.pro\"\n            )\n        }\n    }\n}\n\n# 3) Manual/CI path for a raw APK (align BEFORE signing)\nzipalign -v -p 4 app-release-unsigned.apk app-release-aligned.apk\napksigner sign --ks release.jks --ks-key-alias upload \\\n  --min-sdk-version 24 \\\n  --out app-release.apk app-release-aligned.apk",
        "how_to_verify": "Run: apksigner verify --verbose --print-certs app-release.apk. The output must report 'Verified using v2 scheme (APK Signature Scheme v2): true' and 'v3: true', list your certificate under 'Signer #1', and exit with status 0. A quick negative check: apksigner verify on the old file returned 'DOES NOT VERIFY'. For an AAB, confirm the Play Console accepts the upload and shows your upload key fingerprint.",
        "references": [
            "https://developer.android.com/studio/publish/app-signing",
            "https://developer.android.com/tools/apksigner",
            "https://cwe.mitre.org/data/definitions/347.html",
            "https://mas.owasp.org/MASVS/09-MASVS-RESILIENCE/"
        ]
    },
    "v1-only-signature": {
        "summary": "The APK is signed only with the legacy v1 (JAR) scheme; the modern APK Signing Block (v2/v3) is absent. v1 signs individual ZIP entries rather than the whole file, which is what exposes it to the Janus attack.",
        "why_it_matters": "v1 JAR signing only hashes the contents of ZIP entries, not the bytes of the file as a whole, so an attacker can prepend a malicious classes.dex to the front of your signed APK without invalidating the v1 signature. On Android 5.0-8.0 the Dalvik/ART loader reads the injected DEX while the installer still accepts the untouched v1 signature — this is Janus, CVE-2017-13156. The result is silent code injection into an app that appears correctly signed, enabling a fraudulent update or a trojanized redistribution. v2/v3 protect the entire APK and mitigate this. Mapped to CWE-347 / MASVS-RESILIENCE-3.",
        "fix_steps": [
            "Confirm your minSdkVersion. If it is 24 (Android 7.0) or higher, you can drop v1 entirely because every target device understands v2/v3.",
            "In the release signingConfig, enable v2 and v3 signing; disable v1 when minSdk >= 24, or keep v1 in addition to v2/v3 only if you still support pre-7.0 devices.",
            "Re-sign the release build. apksigner enables v2/v3 by default based on --min-sdk-version; for CI pass the flags explicitly.",
            "If you keep v1 for legacy devices, understand that adding v2/v3 still closes Janus on Android 7.0+ because those versions prefer the v2/v3 signature over v1.",
            "Verify that the APK Signing Block is now present and Janus-safe."
        ],
        "code_example": "# app/build.gradle.kts — signingConfig block\nsigningConfigs {\n    create(\"release\") {\n        storeFile = file(\"release.jks\")\n        storePassword = System.getenv(\"KS_PASS\")\n        keyAlias = \"upload\"\n        keyPassword = System.getenv(\"KEY_PASS\")\n        enableV1Signing = false  // requires minSdk >= 24; set true only for pre-7.0 support\n        enableV2Signing = true\n        enableV3Signing = true\n    }\n}\n\n# Or re-sign an existing artifact with apksigner (align first)\nzipalign -v -p 4 app-release-unsigned.apk app-release-aligned.apk\napksigner sign \\\n  --ks release.jks --ks-key-alias upload \\\n  --min-sdk-version 24 \\\n  --v1-signing-enabled false \\\n  --v2-signing-enabled true \\\n  --v3-signing-enabled true \\\n  --out app-release.apk app-release-aligned.apk",
        "how_to_verify": "Run: apksigner verify --verbose --print-certs app-release.apk. The report must show 'Verified using v2 scheme ... : true' and 'v3 ... : true'. If you disabled v1, 'Verified using v1 scheme (JAR signing): false' is expected and correct for minSdk >= 24. You can also confirm the APK Signing Block exists by checking that the tool no longer warns about JAR-only signing.",
        "references": [
            "https://source.android.com/docs/security/features/apksigning/v2",
            "https://nvd.nist.gov/vuln/detail/CVE-2017-13156",
            "https://developer.android.com/tools/apksigner",
            "https://cwe.mitre.org/data/definitions/347.html"
        ]
    },
    "weak-cert-signature": {
        "summary": "The signing certificate's own signature algorithm uses a broken hash — SHA-1 or MD5 (e.g. SHA1withRSA, MD5withRSA). These hashes are collision-prone, so the certificate binding the signer identity is not trustworthy.",
        "why_it_matters": "MD5 is fully broken and SHA-1 fell to practical collisions (the SHAttered attack), so a certificate whose signature relies on them offers a weak guarantee that the public key really belongs to the stated signer, and it undermines the integrity chain the APK signature depends on. Modern tooling and Play requirements expect SHA-256 or stronger. Note that you cannot simply swap the certificate on an already-published app — an update must be signed by a key the platform recognizes — so remediation for a live app requires APK Signature Scheme v3 key rotation (a signer lineage) or Google Play App Signing key upgrade. Mapped to CWE-327 (Broken/Risky Crypto Algorithm) / MASVS-RESILIENCE-3.",
        "fix_steps": [
            "Generate a new keystore whose certificate is signed with SHA-256, using keytool -sigalg SHA256withRSA with RSA-3072 (or -keyalg EC with the P-256 curve).",
            "For a brand-new app, adopt the new key directly and enroll in Play App Signing.",
            "For an already-published app, do NOT just replace the key: create a v3 signer lineage from the old (SHA-1/MD5) key to the new SHA-256 key with `apksigner rotate`, then sign the release with BOTH signers — the current (old) key as the primary signer and the new key via `--next-signer` — passing `--lineage` and `--rotation-min-sdk-version 28` so the new key takes over from Android 9+ while pre-9 devices still accept the update via the old key's v1/v2 signature; or, if you use Play App Signing, request a signing-key upgrade in the Play Console.",
            "Point the release signingConfig at the new keystore for fresh (non-rotation) builds and rebuild, keeping v2/v3 enabled.",
            "Verify the new (latest-lineage) certificate's signature algorithm is SHA256withRSA (or an ECDSA-with-SHA256 equivalent)."
        ],
        "code_example": "# 1) New key with a SHA-256 certificate signature\nkeytool -genkeypair -v \\\n  -keystore new-release.jks \\\n  -alias upload \\\n  -keyalg RSA -keysize 3072 \\\n  -sigalg SHA256withRSA \\\n  -validity 10000 \\\n  -storetype PKCS12\n\n# 2) Rotate from the old weak key to the new key (creates a v3 signer lineage)\napksigner rotate --out lineage.bin \\\n  --old-signer --ks old-release.jks --ks-key-alias oldalias \\\n  --new-signer --ks new-release.jks --ks-key-alias upload\n\n# 3) Sign the aligned APK. The current (old) key signs the v1/v2 blocks so devices\n#    that already trust it still accept the update; --next-signer + --lineage rotate\n#    to the new SHA-256 key via the v3 scheme. --rotation-min-sdk-version 28 makes the\n#    rotation take effect from Android 9+ (current apksigner defaults rotation to API 33).\nzipalign -v -p 4 app-release-unsigned.apk app-release-aligned.apk\napksigner sign \\\n  --ks old-release.jks --ks-key-alias oldalias \\\n  --next-signer --ks new-release.jks --ks-key-alias upload \\\n  --lineage lineage.bin \\\n  --rotation-min-sdk-version 28 \\\n  --v1-signing-enabled false \\\n  --v2-signing-enabled true \\\n  --v3-signing-enabled true \\\n  --out app-release.apk app-release-aligned.apk",
        "how_to_verify": "Run: apksigner verify --print-certs --verbose app-release.apk and confirm the newest signer's 'certificate ... Signature algorithm:' line reads SHA256withRSA (or SHA256withECDSA) — not SHA1withRSA/MD5withRSA. Cross-check with keytool -printcert -jarfile app-release.apk (or -file cert.pem) which prints 'Signature algorithm name: SHA256withRSA'. When a lineage was used, apksigner also reports 'Verified for SourceStamp' / rotation details and validates the old-to-new signer chain, and the lineage's terminal certificate is the SHA-256 key.",
        "references": [
            "https://developer.android.com/studio/publish/app-signing",
            "https://source.android.com/docs/security/features/apksigning/v3",
            "https://cwe.mitre.org/data/definitions/327.html",
            "https://mas.owasp.org/MASTG/0x05e-Testing-Cryptography/"
        ]
    },
    "debug-certificate": {
        "summary": "The APK is signed with the public Android debug key (CN=Android Debug, O=Android). Android Studio auto-generates this key in ~/.android/debug.keystore with the well-known password 'android' — it is identical across every developer and must never be used to distribute an app.",
        "why_it_matters": "The debug key and its keystore password are publicly known, so anyone can produce a build that Android treats as signed by the very same identity as yours. That defeats update integrity (an attacker can craft an 'update' with a matching signer and hijack the app), any signature-level permissions or shared-userId you rely on, and app-identity checks. Google Play outright rejects debug-signed uploads, and the app has effectively no authenticity guarantee in the field. This is CWE-321 (Use of Hard-coded Cryptographic Key) / MASVS-RESILIENCE-3.",
        "fix_steps": [
            "Create a private release keystore with keytool (RSA-3072/EC P-256, SHA256withRSA) and keep it out of source control.",
            "Add a 'release' signingConfig backed by git-ignored keystore.properties credentials.",
            "Attach that signingConfig to the release buildType and make sure the release build does NOT fall back to debug signing.",
            "Build the shippable artifact from the release variant — ./gradlew bundleRelease or assembleRelease — never assembleDebug.",
            "Verify the signer certificate is your release identity and not 'CN=Android Debug'."
        ],
        "code_example": "# app/build.gradle.kts\nimport java.io.FileInputStream\nimport java.util.Properties\n\nval keystoreProps = Properties().apply {\n    val f = rootProject.file(\"keystore.properties\") // git-ignored\n    if (f.exists()) load(FileInputStream(f))\n}\n\nandroid {\n    signingConfigs {\n        create(\"release\") {\n            storeFile = file(keystoreProps.getProperty(\"storeFile\"))\n            storePassword = keystoreProps.getProperty(\"storePassword\")\n            keyAlias = keystoreProps.getProperty(\"keyAlias\")\n            keyPassword = keystoreProps.getProperty(\"keyPassword\")\n            enableV2Signing = true\n            enableV3Signing = true\n        }\n    }\n    buildTypes {\n        getByName(\"release\") {\n            signingConfig = signingConfigs.getByName(\"release\") // NOT the debug config\n            isMinifyEnabled = true\n            proguardFiles(\n                getDefaultProguardFile(\"proguard-android-optimize.txt\"),\n                \"proguard-rules.pro\"\n            )\n        }\n    }\n}\n\n# keystore.properties (do not commit)\n# storeFile=../release.jks\n# storePassword=********\n# keyAlias=upload\n# keyPassword=********\n\n# Build the release variant, then confirm the signer\n./gradlew bundleRelease",
        "how_to_verify": "Run: apksigner verify --print-certs --verbose app-release.apk. The 'Signer #1 certificate DN' must be your organization's distinguished name — it must NOT be the debug identity 'CN=Android Debug, O=Android, C=US'. You can also run keytool -printcert -jarfile app-release.apk and confirm Owner/Issuer are your release identity. As a guard, compare the printed SHA-256 fingerprint against the debug keystore's (keytool -list -v -keystore ~/.android/debug.keystore -storepass android) and ensure they differ.",
        "references": [
            "https://developer.android.com/studio/publish/app-signing",
            "https://developer.android.com/tools/apksigner",
            "https://cwe.mitre.org/data/definitions/321.html",
            "https://mas.owasp.org/MASVS/09-MASVS-RESILIENCE/"
        ]
    },
    "hardcoded-secret": {
        "summary": "Your APK contains API keys, passwords, tokens, or other credentials embedded directly in the compiled code or resources. Because an APK is trivial to unpack, any string baked into it must be treated as public.",
        "why_it_matters": "APKs are shipped to every user's device and can be decompiled in seconds with apktool, jadx, or `strings`. An attacker who extracts a live key can impersonate your app, run up billing on paid APIs (Google Maps, Twilio, cloud), read/write your backend data, or pivot into your infrastructure if the secret is a signing or admin credential. ProGuard/R8 obfuscation does NOT hide string constants, so the value is recoverable regardless of minification. This maps to CWE-798 (Use of Hard-coded Credentials) and OWASP MASVS-CRYPTO/MASVS-STORAGE.",
        "fix_steps": [
            "Treat the leaked secret as compromised: rotate/revoke it immediately in the issuing console before shipping any fix.",
            "Classify the secret. Client-only public identifiers (e.g. a Google Maps API key) belong in the manifest but MUST be locked down with API/platform restrictions server-side, not hidden. True secrets (signing keys, admin tokens, symmetric keys, DB passwords) must NEVER ship in the client.",
            "Move true secrets to your backend. Have the app authenticate the user, then call your server, which holds the secret and proxies the third-party request. The secret never leaves your infrastructure.",
            "For build-time non-secret config, inject via Gradle `buildConfigField` from a git-ignored `local.properties` / `secrets.properties` or CI environment variables so values are never committed to source control.",
            "For values that must live on-device (e.g. a token cached after login), store them in the Android Keystore (or EncryptedSharedPreferences — now deprecated but still functional on Android 14/15), not in code or plain resources.",
            "Add a secrets scanner (gitleaks, truffleHog, or the Secrets Gradle Plugin) to CI to block re-introduction, and remove the old secret from git history.",
            "Rebuild and re-scan the APK to confirm the string is gone."
        ],
        "code_example": "// settings/build config: keep secrets OUT of the APK, inject non-secret config at build time\n\n// gradle.properties or CI env — file is in .gitignore, NOT committed\n// MAPS_API_KEY=AIza...restricted-to-your-package-and-sha1\n\n// app/build.gradle.kts\nandroid {\n    defaultConfig {\n        // findProperty reads -P flags / gradle.properties / ORG_GRADLE_PROJECT_* env vars;\n        // System.getenv covers a plainly-named CI env var. Never hard-code the value here.\n        val mapsKey = (project.findProperty(\"MAPS_API_KEY\") as String?)\n            ?: System.getenv(\"MAPS_API_KEY\") ?: \"\"\n        buildConfigField(\"String\", \"MAPS_API_KEY\", \"\\\"$mapsKey\\\"\")\n    }\n    buildFeatures { buildConfig = true }\n}\n\n// For a TRUE secret that must exist on device after login — encrypt at rest.\n// NOTE: androidx.security:security-crypto (EncryptedSharedPreferences/MasterKey) is\n// deprecated (still functional on Android 14/15). For new code prefer Google Tink or a\n// Keystore-backed scheme; the pattern below stays valid if you already depend on it.\nval masterKey = MasterKey.Builder(context)\n    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)\n    .build()\n\nval prefs = EncryptedSharedPreferences.create(\n    context,\n    \"secure_prefs\",\n    masterKey,\n    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,\n    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM\n)\nprefs.edit().putString(\"session_token\", tokenFromServer).apply()\n\n// Dependency: implementation(\"androidx.security:security-crypto:1.1.0-alpha06\")",
        "how_to_verify": "Build the release APK, then run `apktool d app-release.apk` and grep the smali/resources, or run `strings app-release.apk | grep -Ei 'api[_-]?key|secret|password|token|AIza|sk_live'`. Decompile with `jadx app-release.apk` and search for the value. Confirm the string does not appear and that BuildConfig only holds non-secret, restricted values. Re-run your platform scan and the gitleaks/truffleHog CI job — both should report clean.",
        "references": [
            "https://developer.android.com/privacy-and-security/security-tips#UserData",
            "https://cwe.mitre.org/data/definitions/798.html",
            "https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0003/",
            "https://github.com/google/secrets-gradle-plugin"
        ]
    },
    "possible-hardcoded-secret": {
        "summary": "The scanner found strings that pattern-match common secret formats (high-entropy blobs, base64/hex chunks, `key=`/`token=` assignments) but could not confirm they are live credentials. These are lower-confidence candidates that a human must triage.",
        "why_it_matters": "Regex/entropy heuristics produce both real leaks and false positives (UUIDs, asset hashes, resource IDs, sample data). Every unconfirmed match is a decision you must make: if even one is a real credential, the same catastrophic exposure as a confirmed hard-coded secret applies (CWE-798, CWE-200 information exposure). Ignoring these because they are 'low confidence' is how real keys slip through; conversely, treating harmless hashes as secrets wastes effort. The goal is disciplined triage. Aligns with OWASP MASVS-STORAGE / MASTG static-analysis testing.",
        "fix_steps": [
            "Triage each candidate: locate the string in the decompiled code/resources and determine what it actually is (credential, hash, UUID, public identifier, test fixture, or opaque config).",
            "If it is or could be a live secret, treat it exactly like a confirmed hard-coded secret: rotate it and follow the hardcoded-secret remediation (move to backend or Keystore/EncryptedSharedPreferences).",
            "If it is a legitimately public value (public key for pinning, OAuth client ID, non-secret config), keep it but document why it is safe so the finding can be dismissed with justification.",
            "If it is a genuine false positive (asset checksum, generated ID), suppress it via the scanner's allowlist/baseline with a comment rather than deleting the check.",
            "Wire a secrets scanner with an entropy threshold and an allowlist into CI so future candidates are triaged at PR time, not release time.",
            "Record the triage decision (owner, date, rationale) so re-scans don't repeatedly surface resolved items."
        ],
        "code_example": "# Triage candidates locally before deciding (jadx decompiles to .java, not smali)\njadx -d out app-release.apk\n# NOTE: grep -E (GNU ERE) does not support the (?i) inline flag — use the -i flag instead\ngrep -rEni --include=*.java \\\n     -e '[A-Za-z0-9+/]{32,}={0,2}' \\\n     -e '(secret|token|passwd|password|api[_-]?key)[[:space:]]*[:=]' out/\n\n# For confirmed false positives, baseline them explicitly (gitleaks example)\n# .gitleaks.toml\n[allowlist]\n  description = \"Reviewed non-secret values (see SECURITY-triage.md)\"\n  regexes = [\n    '''sha256-[A-Fa-f0-9]{64}''',   # asset integrity hashes, not credentials\n  ]\n  paths = [\n    '''app/src/test/.*''',           # test fixtures\n  ]\n\n# Enforce in CI so new candidates fail the build\n# .github/workflows/secrets.yml\n#   - uses: gitleaks/gitleaks-action@v2\n#     env: { GITLEAKS_CONFIG: .gitleaks.toml }",
        "how_to_verify": "After triage, re-run the platform scan; every remaining `possible-hardcoded-secret` item should be either resolved (moved off-device) or covered by a documented allowlist entry. Confirm the CI gitleaks/truffleHog job passes with the baseline in place and that a deliberately planted fake key in a new commit causes the job to fail (proving the gate works). Ensure no real credential remains via `strings app-release.apk` review of the flagged values.",
        "references": [
            "https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0003/",
            "https://cwe.mitre.org/data/definitions/200.html",
            "https://cwe.mitre.org/data/definitions/798.html",
            "https://github.com/gitleaks/gitleaks"
        ]
    },
    "weak-cryptography": {
        "summary": "The app uses cryptographic primitives that are broken or deprecated: block ciphers DES/3DES/RC4, ECB block-cipher mode, or the hash functions MD5/SHA-1. These no longer provide the security they imply and must be replaced with modern algorithms.",
        "why_it_matters": "DES/3DES have inadequate key/block size (Sweet32 birthday attacks on 64-bit blocks); RC4 has practical keystream biases; ECB mode leaks plaintext structure because identical blocks encrypt identically (the classic 'ECB penguin'). MD5 and SHA-1 are collision-broken, so they must not be used for signatures, integrity, or password handling. Using these lets an attacker forge integrity checks, recover or tamper with encrypted data, or produce colliding artifacts. This is CWE-327 (Broken/Risky Crypto Algorithm) and CWE-328 (Weak Hash), and directly violates OWASP MASVS-CRYPTO-1/2.",
        "fix_steps": [
            "Inventory every crypto call: search for `Cipher.getInstance`, `MessageDigest.getInstance`, `Mac.getInstance`, and any DES/DESede/RC4/ARCFOUR/ECB/MD5/SHA-1 string literals.",
            "Replace symmetric encryption with AES-256 in an authenticated mode: AES/GCM/NoPadding (or use Tink's AEAD which picks safe defaults for you). Never use ECB.",
            "Prefer Google Tink or Jetpack Security over hand-rolled JCA calls so nonce/IV generation and authentication are handled correctly. Generate a fresh random 12-byte IV per GCM operation and never reuse an (key, nonce) pair.",
            "Replace MD5/SHA-1 hashing with SHA-256 or SHA-512. For message authentication use HMAC-SHA-256, not a bare hash.",
            "For password storage/derivation use a memory-hard KDF — Argon2id (via a maintained library) or at minimum PBKDF2WithHmacSHA256 with a high iteration count and per-user salt — never a plain hash.",
            "Store keys in the Android Keystore (hardware-backed where available) rather than in code or files.",
            "Remove the weak algorithm strings entirely and re-run the scan."
        ],
        "code_example": "// Preferred: Google Tink handles mode, IV, and authentication safely\n// implementation(\"com.google.crypto.tink:tink-android:1.13.0\")\nAeadConfig.register()\nval keysetHandle = KeysetHandle.generateNew(\n    KeyTemplates.get(\"AES256_GCM\")   // authenticated AES-256\n)\nval aead = keysetHandle.getPrimitive(Aead::class.java)\nval ciphertext = aead.encrypt(plaintext, associatedData)\nval decrypted  = aead.decrypt(ciphertext, associatedData)\n\n// Plain JCA equivalent if you cannot add Tink — AES-256-GCM, random IV, Keystore key\nval keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, \"AndroidKeyStore\")\nkeyGen.init(\n    KeyGenParameterSpec.Builder(\"data_key\",\n        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)\n        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)\n        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)\n        .setKeySize(256)\n        .build())\nval key = keyGen.generateKey()\n\nval cipher = Cipher.getInstance(\"AES/GCM/NoPadding\")   // NEVER AES/ECB or DES/RC4\ncipher.init(Cipher.ENCRYPT_MODE, key)\nval iv = cipher.iv                                     // 12-byte random IV, store with ciphertext\nval ct = cipher.doFinal(plaintext)\n\n// Hashing: SHA-256 instead of MD5/SHA-1\nval digest = MessageDigest.getInstance(\"SHA-256\").digest(bytes)",
        "how_to_verify": "Grep the decompiled APK for banned tokens: `grep -RniE 'des|desede|rc4|arcfour|/ecb/|md5|sha-?1' out/` should return no crypto usages. Confirm `Cipher.getInstance` calls resolve to `AES/GCM/NoPadding` and hashes to SHA-256+. Write a unit test that encrypting the same plaintext twice yields different ciphertext (proves a fresh IV / non-ECB mode) and that GCM decryption of tampered ciphertext throws `AEADBadTagException`. Re-run the platform scan to confirm the weak-cryptography finding clears.",
        "references": [
            "https://developer.android.com/privacy-and-security/cryptography",
            "https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0014/",
            "https://cwe.mitre.org/data/definitions/327.html",
            "https://cwe.mitre.org/data/definitions/328.html"
        ]
    },
    "webview-js-interface": {
        "summary": "The app calls `WebView.addJavascriptInterface(...)`, exposing native Kotlin/Java methods to JavaScript running in the WebView. If any content loaded can be influenced by an attacker, that JS can reach into your app's native code.",
        "why_it_matters": "A bound interface object lets page JavaScript invoke your `@JavascriptInterface` methods directly. If the WebView loads remote/untrusted content, allows navigation to arbitrary URLs, or is exposed to a man-in-the-middle over cleartext, an attacker's script can call those methods to exfiltrate data, trigger app actions, or (via reflection on older behaviors and rich interfaces) escalate toward code execution. Combined with `setAllowFileAccess`/`file://` loading, it can also read local files. This is CWE-749 (Exposed Dangerous Method) and CWE-79 (XSS into native), and maps to OWASP MASVS-PLATFORM-2 (WebView hardening).",
        "fix_steps": [
            "Question whether you need a JavaScript bridge at all. If the WebView only renders content, remove `addJavascriptInterface` and set `setJavaScriptEnabled(false)`.",
            "If a bridge is required, prefer the modern, safer `WebViewCompat.addWebMessageListener` / `postWebMessage` channel over `addJavascriptInterface`, and restrict it to specific trusted origins via an allowed-origin list.",
            "Only ever bind an interface for content you fully control. Load it from bundled assets or via `WebViewAssetLoader` (https on androidplatform.net) rather than remote HTTP.",
            "Constrain navigation with a `WebViewClient.shouldOverrideUrlLoading` that rejects any origin outside your allowlist, so the bridge is never reachable from attacker-controlled pages.",
            "Minimize the attack surface of the exposed object: expose the fewest methods possible, annotate each with `@JavascriptInterface`, validate all arguments, and never pass through reflection, file, or command APIs.",
            "Disable file and content access unless strictly needed: `setAllowFileAccess(false)`, `setAllowFileAccessFromFileURLs(false)`, `setAllowUniversalAccessFromFileURLs(false)`. Enforce HTTPS-only (no cleartext).",
            "Rebuild and confirm the bridge is only reachable from your own origin."
        ],
        "code_example": "// Preferred modern bridge: origin-scoped WebMessageListener (androidx.webkit)\n// implementation(\"androidx.webkit:webkit:1.12.1\")\nval allowedOrigins = setOf(\"https://app.example.com\")\n\nif (WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) {\n    WebViewCompat.addWebMessageListener(\n        webView,\n        \"appBridge\",                 // window.appBridge in JS\n        allowedOrigins,              // ONLY these origins can talk to native\n    ) { _, message, _, _, replyProxy ->\n        val request = message.data ?: return@addWebMessageListener\n        // validate `request` strictly before acting\n        replyProxy.postMessage(handle(request))\n    }\n}\n\n// If you must use the classic interface, lock everything down:\nwebView.settings.apply {\n    javaScriptEnabled = true\n    allowFileAccess = false\n    allowContentAccess = false\n    allowFileAccessFromFileURLs = false\n    allowUniversalAccessFromFileURLs = false\n}\nwebView.webViewClient = object : WebViewClient() {\n    override fun shouldOverrideUrlLoading(v: WebView, req: WebResourceRequest): Boolean {\n        val host = req.url.host\n        // Block navigation to anything outside our origin so the bridge stays unreachable\n        return host != \"app.example.com\"\n    }\n}\nwebView.addJavascriptInterface(SafeBridge(), \"appBridge\")\n\nclass SafeBridge {\n    @JavascriptInterface                        // required on API 17+; expose minimal surface\n    fun getAppVersion(): String = BuildConfig.VERSION_NAME\n}\n\n// AndroidManifest.xml — forbid cleartext so the WebView can't load http:// content\n// <application android:usesCleartextTraffic=\"false\" ...>",
        "how_to_verify": "Decompile and confirm `addJavascriptInterface` is either absent or paired with a `WebViewClient` that allowlists navigation and a bridge class whose methods are all `@JavascriptInterface`-annotated and argument-validated. Load a test page from a non-allowlisted origin (or intercept traffic with Burp/mitmproxy) and confirm `window.appBridge` is undefined/unreachable there. Verify cleartext is blocked (`usesCleartextTraffic=\"false\"`) and that file-access settings are false. Re-run the platform scan to confirm the finding clears.",
        "references": [
            "https://developer.android.com/develop/ui/views/layout/webapps/webview#BindingJavaScript",
            "https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0031/",
            "https://cwe.mitre.org/data/definitions/749.html",
            "https://developer.android.com/reference/androidx/webkit/WebViewCompat#addWebMessageListener(android.webkit.WebView,java.lang.String,java.util.Set%3Cjava.lang.String%3E,androidx.webkit.WebViewCompat.WebMessageListener)"
        ]
    },
    "debug-artifacts": {
        "summary": "The release APK ships files that belong only in development: original source (.java/.kt), ProGuard/R8 mapping files, test classes, debug databases, sample configs, or backup/log files. These should be stripped from production builds.",
        "why_it_matters": "Shipped source and mapping files hand attackers a readable blueprint of your app, undoing obfuscation and revealing logic, endpoints, and embedded secrets (CWE-540 Inclusion of Sensitive Information in Source Code, CWE-527 Exposure of Version-Control/Build info). Test and debug artifacts can expose staging endpoints, test credentials, or debug-only backdoors, and a debuggable build lets anyone attach a debugger to inspect memory and bypass checks. Bloated APKs also enlarge the attack and reverse-engineering surface. This maps to OWASP MASVS-RESILIENCE / MASVS-CODE (release-build hardening).",
        "fix_steps": [
            "Build release with a proper release build type: enable R8 (`isMinifyEnabled = true`) and resource shrinking (`isShrinkResources = true`), and ensure `debuggable = false` (the default for release).",
            "Verify the release manifest has no `android:debuggable=\"true\"` and that `usesCleartextTraffic` is false; ensure the runtime `FLAG_DEBUGGABLE` is not set.",
            "Keep the R8 mapping.txt for your own crash de-obfuscation, but archive it in CI artifacts / Play Console — never inside the APK. Confirm it is not packaged.",
            "Exclude stray files from packaging with `packaging { resources { excludes += [...] } }` (this block was renamed from `packagingOptions` in AGP 8) and make sure test sources live only under `src/test`/`src/androidTest` (they are not compiled into release by default — verify no one added them to `main`).",
            "Remove sample configs, `.bak`, `.orig`, `*.log`, local databases, and any README/source dropped into `assets/` or `res/raw/`.",
            "Strip logging in release: use R8 rules to remove `android.util.Log` verbose/debug calls, or guard with `if (BuildConfig.DEBUG)`.",
            "Rebuild the release APK/AAB and inspect its contents to confirm only production files remain."
        ],
        "code_example": "// app/build.gradle.kts\nandroid {\n    buildTypes {\n        release {\n            isMinifyEnabled = true          // run R8\n            isShrinkResources = true        // drop unused resources\n            isDebuggable = false            // no debugger attach\n            proguardFiles(\n                getDefaultProguardFile(\"proguard-android-optimize.txt\"),\n                \"proguard-rules.pro\"\n            )\n        }\n    }\n    packaging {\n        resources {\n            excludes += setOf(\n                \"**/*.kotlin_metadata\",\n                \"DebugProbesKt.bin\",\n                \"**/*.java\", \"**/*.kt\",     // no source in the APK\n                \"**/*.bak\", \"**/*.orig\", \"**/*.log\",\n                \"META-INF/*.version\", \"**/README*\"\n            )\n        }\n    }\n}\n\n// proguard-rules.pro — strip Log calls from release, keep mapping generation\n-assumenosideeffects class android.util.Log {\n    public static int v(...);\n    public static int d(...);\n}\n\n# Inspect the built artifact — no source/mapping/test files should be present\nunzip -l app/build/outputs/apk/release/app-release.apk | \\\n  grep -Ei '\\.java$|\\.kt$|mapping\\.txt|/test/|\\.bak$|\\.orig$|\\.log$'\n# (expect no matches)\n\n# Confirm the APK is not debuggable (aapt2 dump also works)\naapt dump badging app-release.apk | grep -i debuggable   # expect empty",
        "how_to_verify": "Run `unzip -l app-release.apk` (or `apkanalyzer files list`) and confirm no `.java`/`.kt` source, `mapping.txt`, test classes, `.bak`/`.orig`/`.log`, or debug DBs are packaged. Run `aapt dump badging app-release.apk | grep debuggable` and confirm it returns nothing (build is not debuggable). Verify the R8 `mapping.txt` exists in `build/outputs/mapping/release/` for your own use but is absent from the APK. Re-run the platform scan to confirm the debug-artifacts finding clears.",
        "references": [
            "https://developer.android.com/build/shrink-code",
            "https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0027/",
            "https://cwe.mitre.org/data/definitions/540.html",
            "https://cwe.mitre.org/data/definitions/527.html"
        ]
    }
}
