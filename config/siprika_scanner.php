<?php

/*
|--------------------------------------------------------------------------
| Pola Pengenal Scanner
|--------------------------------------------------------------------------
|
| Nilai di sini dipakai pemeriksaan bawaan PHP. Pola memakai regex PCRE.
| Grup tangkapan pertama (jika ada) dianggap nomor versi.
|
*/

return [

    // Nama cookie sesi (bagian 23.1). Dicocokkan tanpa membedakan huruf besar/kecil.
    'session_cookies' => [
        'session', 'sess', 'sid', 'phpsessid', 'jsessionid', 'asp.net_sessionid',
        'laravel_session', 'ci_session',
    ],
    'session_cookie_prefixes' => ['wordpress_logged_in'],
    'session_cookie_suffixes' => ['_session', 'session'],

    // Cookie yang memang dibaca JavaScript, tidak diperiksa HttpOnly
    'js_readable_cookies' => ['xsrf-token', 'csrftoken', 'csrf_cookie_name'],

    /*
    | Deteksi CDN/WAF dari header respons
    */
    'cdn' => [
        'Cloudflare' => ['headers' => ['cf-ray' => null, 'server' => '/cloudflare/i']],
        'Akamai' => ['headers' => ['x-akamai-transformed' => null, 'server' => '/akamai/i']],
        'Amazon CloudFront' => ['headers' => ['x-amz-cf-id' => null, 'via' => '/cloudfront/i']],
        'Fastly' => ['headers' => ['x-fastly-request-id' => null, 'x-served-by' => '/cache-/i']],
        'Sucuri' => ['headers' => ['x-sucuri-id' => null, 'server' => '/sucuri/i']],
        'Imperva Incapsula' => ['headers' => ['x-iinfo' => null, 'x-cdn' => '/incapsula/i']],
        'BunnyCDN' => ['headers' => ['server' => '/bunnycdn/i']],
        'Azure Front Door' => ['headers' => ['x-azure-ref' => null]],
        'Google Cloud CDN' => ['headers' => ['via' => '/google/i']],
    ],

    /*
    | Deteksi teknologi dari header, cookie, dan HTML
    */
    'technologies' => [
        // Web server
        'Nginx' => ['category' => 'Web Server', 'headers' => ['server' => '/nginx(?:\/([\d.]+))?/i']],
        'Apache HTTP Server' => ['category' => 'Web Server', 'headers' => ['server' => '/apache(?:\/([\d.]+))?/i']],
        'Microsoft IIS' => ['category' => 'Web Server', 'headers' => ['server' => '/microsoft-iis(?:\/([\d.]+))?/i']],
        'LiteSpeed' => ['category' => 'Web Server', 'headers' => ['server' => '/litespeed/i']],
        'OpenResty' => ['category' => 'Web Server', 'headers' => ['server' => '/openresty(?:\/([\d.]+))?/i']],
        'Caddy' => ['category' => 'Web Server', 'headers' => ['server' => '/caddy/i']],

        // Bahasa dan framework
        'PHP' => ['category' => 'Bahasa Pemrograman', 'headers' => ['x-powered-by' => '/php(?:\/([\d.]+))?/i'], 'cookies' => ['/^phpsessid$/i']],
        'ASP.NET' => ['category' => 'Framework', 'headers' => ['x-powered-by' => '/asp\.net/i', 'x-aspnet-version' => '/([\d.]+)/'], 'cookies' => ['/^asp\.net_sessionid$/i']],
        'Express' => ['category' => 'Framework', 'headers' => ['x-powered-by' => '/express/i']],
        'Laravel' => ['category' => 'Framework', 'cookies' => ['/^laravel_session$/i', '/^xsrf-token$/i']],
        'CodeIgniter' => ['category' => 'Framework', 'cookies' => ['/^ci_session$/i']],
        'Java' => ['category' => 'Bahasa Pemrograman', 'cookies' => ['/^jsessionid$/i']],
        'Next.js' => ['category' => 'Framework', 'headers' => ['x-powered-by' => '/next\.js/i'], 'html' => ['/\/_next\/static\//']],
        'Nuxt.js' => ['category' => 'Framework', 'html' => ['/\/_nuxt\//']],

        // CMS
        'WordPress' => ['category' => 'CMS', 'html' => ['/\/wp-content\//', '/\/wp-includes\//'], 'meta_generator' => '/wordpress\s*([\d.]+)?/i'],
        'Joomla' => ['category' => 'CMS', 'html' => ['/\/media\/jui\//', '/\/components\/com_/'], 'meta_generator' => '/joomla!?\s*([\d.]+)?/i'],
        'Drupal' => ['category' => 'CMS', 'headers' => ['x-generator' => '/drupal\s*([\d.]+)?/i', 'x-drupal-cache' => null], 'html' => ['/\/sites\/default\/files\//'], 'meta_generator' => '/drupal\s*([\d.]+)?/i'],
        'Moodle' => ['category' => 'CMS', 'cookies' => ['/^moodlesession/i'], 'meta_generator' => '/moodle/i'],
        // Batas kata supaya nama fungsi seperti openSidebar() tidak terdeteksi sebagai OpenSID
        'OpenSID' => ['category' => 'CMS', 'html' => ['/\bopensid\b/i']],

        // Library JavaScript dan CSS
        'jQuery' => ['category' => 'Library JavaScript', 'html' => ['/\/jquery(?:\.min)?\.js\?ver=(\d+\.[\d.]+)/i', '/jquery[.-]?([\d]+\.[\d.]+)?(?:\.min)?\.js/i']],
        'Bootstrap' => ['category' => 'Library CSS', 'html' => ['/\/bootstrap(?:\.min)?\.(?:css|js)\?ver=(\d+\.[\d.]+)/i', '/bootstrap[.-]?([\d]+\.[\d.]+)?(?:\.min)?\.(?:css|js)/i']],
        'Font Awesome' => ['category' => 'Library CSS', 'html' => ['/font-?awesome/i']],
        'Vue.js' => ['category' => 'Library JavaScript', 'html' => ['/vue(?:\.runtime)?(?:\.global)?(?:\.min)?\.js/i', '/data-v-[0-9a-f]{8}/']],
        'React' => ['category' => 'Library JavaScript', 'html' => ['/react(?:-dom)?(?:\.production)?(?:\.min)?\.js/i', '/data-reactroot/']],
        'Google Analytics' => ['category' => 'Analitik', 'html' => ['/googletagmanager\.com\/gtag\/js/', '/google-analytics\.com\/(?:analytics|ga)\.js/']],
    ],

    /*
    | Pemeriksaan exposure bawaan. File dianggap terbuka hanya jika isinya
    | cocok dengan pola (status 200 saja tidak cukup).
    */
    'exposures' => [
        ['path' => '/.env', 'name' => 'File .env', 'pattern' => '/^\s*(?:APP_KEY|APP_ENV|DB_HOST|DB_PASSWORD|DB_USERNAME|DB_DATABASE)\s*=/m', 'mask' => 'env'],
        ['path' => '/.git/config', 'name' => 'Konfigurasi Git', 'pattern' => '/^\s*\[core\]\s*$/m', 'mask' => 'none'],
        ['path' => '/.git/HEAD', 'name' => 'Git HEAD', 'pattern' => '/^ref:\s*refs\/heads\//', 'mask' => 'none'],
        ['path' => '/.svn/entries', 'name' => 'Metadata SVN', 'pattern' => '/^(?:\d+\s*$|<\?xml[^>]*>\s*<wc-entries)/m', 'mask' => 'none'],
        ['path' => '/wp-config.php.bak', 'name' => 'Backup wp-config.php', 'pattern' => '/define\(\s*[\'"]DB_(?:NAME|PASSWORD|USER)[\'"]/', 'mask' => 'php'],
        ['path' => '/config.php.bak', 'name' => 'Backup config.php', 'pattern' => '/<\?php[\s\S]*(?:password|passwd|db_)/i', 'mask' => 'php'],
        ['path' => '/backup.sql', 'name' => 'Backup database', 'pattern' => '/(?:CREATE TABLE|INSERT INTO)\s+[`"\w]/i', 'mask' => 'none'],
        ['path' => '/database.sql', 'name' => 'Backup database', 'pattern' => '/(?:CREATE TABLE|INSERT INTO)\s+[`"\w]/i', 'mask' => 'none'],
        ['path' => '/phpinfo.php', 'name' => 'Halaman phpinfo()', 'pattern' => '/<title>\s*(?:PHP\s+[\d.]+\s+-\s+)?phpinfo\(\)\s*<\/title>/i', 'mask' => 'none'],
        ['path' => '/info.php', 'name' => 'Halaman phpinfo()', 'pattern' => '/<title>\s*(?:PHP\s+[\d.]+\s+-\s+)?phpinfo\(\)\s*<\/title>/i', 'mask' => 'none'],
        ['path' => '/server-status', 'name' => 'Apache server-status', 'pattern' => '/<title>\s*Apache Status\s*<\/title>/i', 'mask' => 'none'],
        ['path' => '/storage/logs/laravel.log', 'name' => 'Log aplikasi Laravel', 'pattern' => '/^\[\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}[^\]]*\]\s+\w+\.(?:EMERGENCY|ALERT|CRITICAL|ERROR|WARNING|NOTICE|INFO|DEBUG):/m', 'mask' => 'none'],
        ['path' => '/.DS_Store', 'name' => 'File .DS_Store', 'pattern' => '/^\x00\x00\x00\x01Bud1/', 'mask' => 'binary'],
    ],

    // Direktori yang dicek untuk directory listing
    'listing_paths' => ['/', '/uploads/', '/upload/', '/assets/', '/images/', '/files/', '/backup/', '/wp-content/uploads/'],

    // Mode Cepat hanya memeriksa sebagian path di atas (bagian 3: exposure terbatas)
    'quick_exposure_paths' => ['/.env', '/.git/config', '/.git/HEAD', '/phpinfo.php', '/backup.sql', '/storage/logs/laravel.log'],
    'quick_listing_paths' => ['/', '/uploads/', '/wp-content/uploads/'],
    'listing_pattern' => '/<title>\s*Index of \/|<h1>\s*Index of \/|<title>\s*Directory listing for \//i',

    /*
    | Pola halaman blokir WAF/CDN (bagian 22.4)
    */
    'waf_block_statuses' => [403, 429, 503],
    'waf_block_patterns' => [
        '/attention required! \| cloudflare/i',
        '/cf-error-details|cf-chl-|challenge-platform/i',
        '/sucuri website firewall/i',
        '/incapsula incident id/i',
        '/access denied.*akamai|reference #\d+\.[0-9a-f]+/is',
        '/request unsuccessful\. incapsula/i',
    ],

    /*
    | Pemetaan template Nuclei ke kunci katalog. Kunci array berupa
    | template-id atau "template-id:matcher-name".
    */
    'nuclei_map' => [
        'http-missing-security-headers:strict-transport-security' => 'missing-hsts',
        'http-missing-security-headers:content-security-policy' => 'missing-csp',
        'http-missing-security-headers:x-frame-options' => 'missing-x-frame-options',
        'http-missing-security-headers:x-content-type-options' => 'missing-x-content-type-options',
        'http-missing-security-headers:referrer-policy' => 'missing-referrer-policy',
        'deprecated-tls' => 'tls-legacy-protocol',
        'tls-version' => null,
        'expired-ssl' => 'tls-cert-invalid',
        'self-signed-ssl' => 'tls-cert-invalid',
        'mismatched-ssl-certificate' => 'tls-cert-invalid',
        'untrusted-root-certificate' => 'tls-chain-incomplete',
        'weak-cipher-suites' => 'tls-weak-cipher',
        'directory-listing' => 'directory-listing',
        'dir-listing' => 'directory-listing',
        'generic-directory-listing' => 'directory-listing',
    ],

    // Template weak-cipher-suites menganggap hampir semua cipher TLS 1.0/1.1 lemah, termasuk AES-CBC biasa
    // (contoh TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA) yang sudah tercakup tls-legacy-protocol. Hanya cipher yang
    // namanya memuat pola berikut (NULL, anon, EXPORT, RC4, RC2, DES/3DES, IDEA; kategori lemah testssl.sh)
    // yang menjadi tls-weak-cipher. Jika Nuclei tidak menyertakan nama cipher, hasilnya tetap dipakai.
    'nuclei_weak_cipher_patterns' => ['NULL', 'anon', 'EXPORT', 'RC4', 'RC2', 'DES', 'IDEA'],

    // Template Nuclei bertag berikut dipetakan ke exposed-sensitive-file jika severity minimal nilai di bawah.
    // Contoh di bagian 23.1 (.env high, .git/config medium, file backup medium) semuanya minimal medium.
    // Template berseverity low (contoh .editorconfig) menjadi baris nuclei:<template-id> dengan dampak
    // sesuai severity-nya (bagian 24.4), bukan File Sensitif dengan IR 23.
    'nuclei_exposure_tags' => ['exposure', 'config', 'backup', 'logs'],
    'nuclei_exposure_min_severity' => 'medium',

    // Template bertag tech yang bukan nama teknologi. waf-detect sering cocok dengan beberapa WAF sekaligus
    // (contoh varnish, apachegeneric, dan alertlogic pada server LiteSpeed), CDN/WAF memakai deteksi bawaan.
    'nuclei_not_technology' => ['waf-detect', 's3-detect'],

    // Kunci yang hanya berlaku pada respons HTTPS (bagian 23.1: header HSTS pada respons HTTP diabaikan)
    'https_only_findings' => ['missing-hsts'],

    // Nama sumber temuan dan tool di halaman hasil
    'source_labels' => [
        'internal' => 'Pemeriksaan bawaan',
        'nuclei' => 'Nuclei',
        'testssl' => 'testssl.sh',
        'whatweb' => 'WhatWeb',
        'nmap' => 'Nmap',
        'zap' => 'OWASP ZAP',
        'ai' => 'AI lokal',
    ],

    /*
    | Pemetaan alert passive scan OWASP ZAP (alertRef, atau pluginId jika tanpa
    | nomor varian) ke kunci katalog. Alert lain hanya tampil di Coverage dan
    | tidak menjadi finding. Alert cookie disaring dengan aturan insecure-cookie
    | (CookieRules), alert header teknologi hanya dipakai jika memuat nomor versi.
    */
    'zap_map' => [
        '10035-1' => 'missing-hsts',                    // Strict-Transport-Security Header Not Set
        '10035-2' => 'missing-hsts',                    // Strict-Transport-Security Disabled (max-age=0)
        '10038-1' => 'missing-csp',                     // Content Security Policy (CSP) Header Not Set
        '10020-1' => 'missing-x-frame-options',         // Missing Anti-clickjacking Header
        '10021' => 'missing-x-content-type-options',    // X-Content-Type-Options Header Missing
        '10011' => 'insecure-cookie',                   // Cookie Without Secure Flag
        '10010' => 'insecure-cookie',                   // Cookie No HttpOnly Flag
        '10054-1' => 'insecure-cookie',                 // Cookie without SameSite Attribute
        '10036-2' => 'server-version-disclosure',       // Server Leaks Version Information via "Server"
        '10037' => 'server-version-disclosure',         // X-Powered-By
        '10061' => 'server-version-disclosure',         // X-AspNet-Version
    ],

    /*
    |--------------------------------------------------------------------------
    | Coverage per Kunci Katalog (bagian 22.10)
    |--------------------------------------------------------------------------
    |
    | Pemeriksaan bawaan (kunci observation) yang menilai setiap kunci katalog.
    | Kunci pemeriksaan (security-headers, tls, exposure) hanya muncul sebagai
    | observation ERROR saat pemeriksaan itu gagal atau melewati batas waktu.
    | Tool eksternal (Nuclei, testssl.sh) tidak ditulis di sini: tool mencatat
    | sendiri kunci yang benar-benar dinilainya di raw.assessed_keys, karena
    | cakupannya bergantung pada profil mode, URL, dan respons website.
    | Kunci tanpa pemeriksa yang berhasil dicatat NOT ASSESSED, bukan PASS.
    |
    */

    'catalog_coverage' => [
        'no-https' => ['https'],
        'http-not-redirected' => ['http-redirect'],
        'missing-hsts' => ['header-hsts', 'security-headers'],
        'missing-csp' => ['header-csp', 'security-headers'],
        'missing-x-frame-options' => ['header-x-frame-options', 'security-headers'],
        'missing-x-content-type-options' => ['header-x-content-type-options', 'security-headers'],
        'missing-referrer-policy' => ['header-referrer-policy', 'security-headers'],
        'insecure-cookie' => ['cookie-security'],
        'tls-cert-invalid' => ['tls-certificate', 'tls'],
        'tls-chain-incomplete' => ['tls-chain', 'tls'],
        'tls-cert-expiring' => ['tls-expiry', 'tls'],
        'tls-legacy-protocol' => ['tls-protocol', 'tls'],
        // Tidak ada pemeriksaan bawaan: hanya Nuclei dan testssl.sh
        'tls-weak-cipher' => [],
        'server-version-disclosure' => ['server-version', 'security-headers'],
        'directory-listing' => ['directory-listing', 'exposure'],
        'exposed-sensitive-file' => ['exposure-files', 'exposure'],
    ],

    // Kunci yang hanya dapat dinilai lewat HTTPS. Tool yang memindai URL http:// tidak menilai kunci ini.
    'https_keys' => ['missing-hsts', 'insecure-cookie', 'tls-cert-invalid', 'tls-chain-incomplete', 'tls-legacy-protocol', 'tls-weak-cipher'],

    // Kunci yang dinilai dari halaman utama. Tidak dinilai jika respons berupa halaman blokir WAF (bagian 22.4)
    // atau redirect yang tidak diikuti (bagian 22.11), dan hasil Nuclei untuk kunci ini dibuang.
    'page_keys' => ['missing-hsts', 'missing-csp', 'missing-x-frame-options', 'missing-x-content-type-options', 'missing-referrer-policy', 'insecure-cookie', 'server-version-disclosure'],

    // Kunci yang tidak dapat dinyatakan PASS jika WAF memblokir SIPRIKA, karena permintaan ke path lain juga
    // terblokir (bagian 22.10). Temuan berdasarkan isi file tetap sah sehingga tidak dibuang.
    'waf_limited_keys' => ['directory-listing', 'exposed-sensitive-file'],

    // Kriteria bagian 23.1 untuk kunci ini juga menghitung tag meta CSP, meta referrer, dan direktif CSP
    // frame-ancestors, sedangkan template Nuclei dan aturan ZAP hanya melihat header. Jika pemeriksaan bawaan
    // menyatakan PASS pada halaman yang sama, temuan tool untuk kunci ini dibuang supaya tidak menjadi FAIL palsu.
    'builtin_authoritative_keys' => ['missing-hsts', 'missing-csp', 'missing-x-frame-options', 'missing-x-content-type-options', 'missing-referrer-policy'],

];
