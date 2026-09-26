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
            'tls' => 15,
            'exposure' => ['quick' => 10, 'standard' => 25],
            'ports' => 15,
            'nuclei' => ['quick' => 200, 'standard' => 1300],
            'testssl' => 80,
            'whatweb' => 10,
            'zap-passive' => 1,
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
            // Batas waktu Nuclei per website (detik). Profil Standar penuh sekitar 7.000 request pada 5 request per detik.
            'timeout' => (int) env('NUCLEI_TIMEOUT', 1800),
            'rate_limit' => 5,
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
    ],

];
