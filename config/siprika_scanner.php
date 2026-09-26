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

    // Template Nuclei bertag berikut dipetakan ke exposed-sensitive-file jika severity minimal low
    'nuclei_exposure_tags' => ['exposure', 'config', 'backup', 'logs'],

    // Kunci yang hanya berlaku pada respons HTTPS (bagian 23.1: header HSTS pada respons HTTP diabaikan)
    'https_only_findings' => ['missing-hsts'],

];
