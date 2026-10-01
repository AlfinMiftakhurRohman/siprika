<?php

$list = fn (?string $value) => array_values(array_filter(array_map(
    fn (string $item) => strtolower(trim($item, " \t\n\r\0\x0B.")),
    explode(',', (string) $value)
)));

return [

    /*
    |--------------------------------------------------------------------------
    | Domain yang Boleh Dipindai
    |--------------------------------------------------------------------------
    |
    | Daftar domain dipisah koma. Subdomain dari domain ini ikut diizinkan.
    | URL di luar daftar ini ditolak saat input. Kosong atau "*" berarti semua
    | domain boleh diperiksa. Localhost, alamat IP, dan domain yang mengarah ke
    | IP privat tetap ditolak (perlindungan SSRF).
    |
    */

    'allowed_domains' => $list(env('SCAN_ALLOWED_DOMAINS', '*')),

    'max_urls_per_batch' => 100,

    /*
    |--------------------------------------------------------------------------
    | Pemindaian
    |--------------------------------------------------------------------------
    */

    'scan' => [
        // Batas waktu total pemeriksaan satu website (detik): Mode Standar dan Mode Cepat (bagian 26)
        'target_timeout' => (int) env('SCAN_TARGET_TIMEOUT', 2700),
        'quick_target_timeout' => (int) env('SCAN_QUICK_TARGET_TIMEOUT', 600),

        // Laptop offline (server DNS tidak dapat dihubungi, contoh Wi-Fi terputus): antrean dijeda dan dicek setiap
        // offline_check_interval detik sampai koneksi kembali. Lewat offline_wait detik, website tetap diperiksa
        // dan dicatat DNS gagal.
        'offline_wait' => (int) env('SCAN_OFFLINE_WAIT', 1800),
        'offline_check_interval' => 15,

        'user_agent' => env('SCAN_USER_AGENT', 'SIPRIKA/1.0 (Diskominfo Jember)'),

        'max_redirects' => 5,

        // Batas waktu satu permintaan HTTP (detik)
        'http_timeout' => 20,
        'connect_timeout' => 10,

        // Jeda antar permintaan tambahan (exposure), menjaga di bawah 5 request per detik
        'request_delay_ms' => 250,

        // Ukuran maksimal isi respons yang dibaca (byte)
        'max_body_bytes' => 512 * 1024,

        // Path file CA bundle. Kosong berarti memakai CA bawaan sistem
        // (di Windows, PHP memakai certificate store Windows).
        'ca_bundle' => env('SCAN_CA_BUNDLE'),

        // Website dengan sertifikat valid yang diketahui, untuk menguji verifikasi TLS sebelum dipakai (bagian 22.5)
        'tls_selftest_host' => env('SCAN_TLS_SELFTEST_HOST', 'www.google.com'),

        // Port web yang dicek pada pemeriksaan Port/Web Service
        'web_ports' => [80, 443, 8080, 8443, 8000, 8888],
        'port_timeout' => 3,

        // Perkiraan lama setiap tahap (detik) untuk persentase progress, dari pengukuran scan sungguhan.
        // Nilai per mode ditulis sebagai ['quick' => ..., 'standard' => ...].
        'expected_seconds' => [
            'target-validation' => 2,
            'http-info' => 5,
            'security-headers' => 1,
            'cookie-security' => 1,
            'technology' => 1,
            'tls' => 5,
            'exposure' => ['quick' => 5, 'standard' => 15],
            'ports' => 15,
            'nuclei' => ['quick' => 85, 'standard' => 445],
            'testssl' => 80,
            'whatweb' => 10,
            'zap-passive' => 15,
            'ai-analysis' => 60,
            'risk-assessment' => 1,
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Tool Eksternal (opsional)
    |--------------------------------------------------------------------------
    |
    | Isi dengan perintah untuk menjalankan tool. Boleh berisi prefix, contoh
    | "wsl testssl.sh" untuk menjalankan testssl.sh lewat WSL. Jika kosong,
    | pemeriksaan tool tersebut dicatat NOT ASSESSED.
    |
    */

    'tools' => [
        'nuclei' => [
            'command' => env('NUCLEI_PATH'),
            // Batas waktu Nuclei per website (detik). Profil Standar penuh sekitar 7.000 request pada 15 request per detik.
            'timeout' => (int) env('NUCLEI_TIMEOUT', 1800),
            // Maksimal request per detik per website (blueprint bagian 26). Template yang berjalan bersamaan (-c)
            // disamakan supaya batas ini benar-benar tercapai walaupun respons website agak lambat.
            'rate_limit' => (int) env('NUCLEI_RATE_LIMIT', 15),
            /*
             * Website yang kewalahan atau membatasi request. Request HTTP ke website yang gagal (timeout, koneksi ditolak
             * atau diputus) dicatat Nuclei di -elog, lalu template-nya diulang pada retry_rate_limit. Jika halaman utama
             * berubah menjadi 429/5xx/halaman blokir WAF, seluruh run diulang setelah jeda retry_cooldown detik pada
             * blocked_rate_limit, dan run berikutnya tetap pada kecepatan itu. Nuclei berhenti memeriksa website setelah
             * max_host_errors (-mhe). Jika setelah diulang masih ada max_failed_requests request gagal atau website masih
             * memblokir, Nuclei dicatat ERROR (website PARTIAL). Uji e-sakip pada 15 request/detik: 0 sampai 11 dari
             * sekitar 7.000 request timeout secara acak, semuanya berhasil saat diulang.
             */
            'retry_rate_limit' => (int) env('NUCLEI_RETRY_RATE_LIMIT', 10),
            'blocked_rate_limit' => (int) env('NUCLEI_BLOCKED_RATE_LIMIT', 5),
            'retry_cooldown' => 30,
            'max_host_errors' => 30,
            'max_failed_requests' => 10,
            /*
             * Profil template per mode (bagian 26). Satu profil berisi satu atau beberapa run karena
             * filter Nuclei (tags, severity, id) digabung dengan AND. Setiap run: tags, severity, ids.
             *
             * Mode Cepat: template informasi penting (teknologi, WAF, header, TLS) ditambah tag exposure,
             * misconfig, tech, ssl dengan severity high dan critical, sekitar 1.000 request supaya selesai
             * jauh di bawah batas 10 menit. Semua severity untuk tag tersebut sekitar 5.500 request.
             * Mode Standar: semua severity ditambah tag cve.
             */
            'profiles' => [
                'quick' => [
                    ['ids' => ['tech-detect', 'waf-detect', 'http-missing-security-headers', 'tls-version', 'deprecated-tls', 'weak-cipher-suites', 'expired-ssl', 'self-signed-ssl', 'mismatched-ssl-certificate', 'untrusted-root-certificate']],
                    ['tags' => ['exposure', 'misconfig', 'tech', 'ssl'], 'severity' => ['high', 'critical']],
                ],
                'standard' => [
                    ['tags' => ['exposure', 'misconfig', 'tech', 'ssl', 'cve']],
                ],
            ],
            /*
             * Kunci katalog yang dicakup template setiap profil (bagian 22.10), dicek dari template yang terpasang.
             * Template cookie berseverity info sehingga hanya ada di profil Standar. Tidak ada template directory
             * listing di kedua profil (template directory-listing bertag fuzz dan dikecualikan).
             */
            'profile_keys' => [
                'quick' => ['missing-hsts', 'missing-csp', 'missing-x-frame-options', 'missing-x-content-type-options', 'missing-referrer-policy', 'tls-cert-invalid', 'tls-chain-incomplete', 'tls-legacy-protocol', 'tls-weak-cipher', 'exposed-sensitive-file'],
                'standard' => ['missing-hsts', 'missing-csp', 'missing-x-frame-options', 'missing-x-content-type-options', 'missing-referrer-policy', 'insecure-cookie', 'tls-cert-invalid', 'tls-chain-incomplete', 'tls-legacy-protocol', 'tls-weak-cipher', 'exposed-sensitive-file'],
            ],
            'exclude_tags' => ['intrusive', 'dos', 'fuzz', 'default-login', 'bruteforce', 'brute-force', 'auth-bypass', 'sqli', 'rce', 'xss', 'lfi', 'file-upload', 'oast'],
        ],
        'testssl' => [
            'command' => env('TESTSSL_PATH'),
            'timeout' => (int) env('TESTSSL_TIMEOUT', 420),
        ],
        'whatweb' => [
            'command' => env('WHATWEB_PATH'),
            'timeout' => (int) env('WHATWEB_TIMEOUT', 120),
        ],
        'nmap' => [
            'command' => env('NMAP_PATH'),
            'timeout' => (int) env('NMAP_TIMEOUT', 300),
        ],
        // OWASP ZAP daemon untuk passive scan Mode Standar (bagian 4). Kosong berarti NOT ASSESSED.
        'zap' => [
            'url' => env('ZAP_URL'),
            'api_key' => env('ZAP_API_KEY'),
            // Batas waktu passive scan satu website (detik)
            'timeout' => (int) env('ZAP_TIMEOUT', 120),
            // Perintah ZAP daemon yang ikut dijalankan oleh "php artisan siprika:serve" (opsional)
            'server_command' => env('ZAP_SERVER_COMMAND'),
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | AI Lokal (llama.cpp / llama-server)
    |--------------------------------------------------------------------------
    */

    'ai' => [
        'enabled' => (bool) env('AI_ENABLED', false),
        'url' => env('AI_URL', 'http://127.0.0.1:8081'),
        'model' => env('AI_MODEL', 'qwen2.5-7b-instruct.Q4_K_M.gguf'),
        'timeout' => (int) env('AI_TIMEOUT', 60),
        // Perintah llama-server yang ikut dijalankan oleh "php artisan siprika:serve" (opsional)
        'server_command' => env('AI_SERVER_COMMAND'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Export Excel
    |--------------------------------------------------------------------------
    */

    'excel' => [
        'template' => env('RISK_REGISTER_TEMPLATE', resource_path('templates/risk-register-template.xlsx')),
        'sheet' => 'Perangkat Lunak',
        'first_row' => 7,
        // Jumlah baris data bawaan template (baris 7 sampai 11)
        'template_rows' => 5,
        'risk_no_prefix' => 'PL-',

        // Rumus persentase di sheet Ringkasan untuk setiap baris aset ({row} = nomor baris). Template aslinya
        // keliru membagi dengan jumlah Unacceptable (E10 benar, E11 sampai E14 = C/D) dan tanpa pengaman
        // pembagian nol. Baris yang merujuk ke sheet lain dari labelnya juga diarahkan ke sheet sesuai label.
        'summary_sheet' => 'Ringkasan',
        'summary_formulas' => [
            // % Acceptable of Inherent Risk = Acceptable inherent / jumlah risiko
            'E' => 'IFERROR(C{row}/B{row},0)',
            // % Acceptable of Residual Risk = Acceptable residual / jumlah risiko
            'H' => 'IFERROR(F{row}/B{row},0)',
        ],
    ],

];
