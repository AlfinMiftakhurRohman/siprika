<?php

/*
|--------------------------------------------------------------------------
| Katalog Finding
|--------------------------------------------------------------------------
|
| Kunci tetap untuk setiap finding (bagian 23 dan 24 blueprint). Kategori,
| ancaman, kerawanan, dan area dampak harus sesuai daftar di template.
| Teks deskriptif dipakai sebagai cadangan jika AI tidak aktif atau gagal.
|
| severity: tingkat keparahan teknis (info, low, medium, high, critical).
| impact / likelihood: nilai 1-5 untuk Risk Engine.
|
*/

$infra = [
    'category' => 'Keamanan Infrastruktur',
    'threat' => 'Terjadi peretasan pada aplikasi',
    'vulnerability' => 'Lemahnya mekanisme kriptografi aplikasi',
    'impact_area' => 'Operasional dan Aset TIK',
];

$misconfig = [
    'category' => 'Ketidaksesuaian Pengelolaan Aplikasi',
    'threat' => 'Terjadi peretasan pada aplikasi',
    'vulnerability' => 'Adanya miss konfigurasi pada aplikasi',
    'impact_area' => 'Operasional dan Aset TIK',
];

return [

    'no-https' => $infra + [
        'title' => 'Website tidak mendukung HTTPS',
        'severity' => 'high',
        'impact' => 3,
        'likelihood' => 2,
        'description' => 'Website hanya dapat diakses melalui HTTP tanpa enkripsi. Data yang dikirim antara pengguna dan server dapat dibaca atau diubah oleh pihak yang berada di jalur jaringan.',
        'impact_description' => 'Data pengguna, termasuk data login, berpotensi disadap atau diubah saat dikirim melalui jaringan.',
        'recommendation' => 'Pasang sertifikat TLS yang valid dan aktifkan HTTPS pada port 443.',
        'output' => 'Website dapat diakses melalui HTTPS dengan sertifikat yang valid.',
        'additional_control' => 'Pantau masa berlaku sertifikat dan konfigurasi TLS secara berkala.',
    ],

    'http-not-redirected' => $infra + [
        'title' => 'HTTP tidak dialihkan ke HTTPS',
        'severity' => 'medium',
        'impact' => 2,
        'likelihood' => 2,
        'description' => 'Akses melalui http:// ditampilkan langsung tanpa dialihkan ke https://, sehingga pengguna dapat tetap memakai koneksi tanpa enkripsi.',
        'impact_description' => 'Pengguna yang membuka alamat http:// berkomunikasi tanpa enkripsi sehingga datanya berpotensi disadap.',
        'recommendation' => 'Terapkan redirect permanen (301) dari seluruh alamat http:// ke https://.',
        'output' => 'Seluruh akses HTTP dialihkan otomatis ke HTTPS.',
        'additional_control' => 'Terapkan HSTS setelah redirect HTTPS berjalan.',
    ],

    'missing-hsts' => $infra + [
        'title' => 'Header Strict-Transport-Security tidak diterapkan',
        'severity' => 'low',
        'impact' => 2,
        'likelihood' => 2,
        'description' => 'Respons HTTPS tidak memiliki header Strict-Transport-Security (HSTS) atau nilainya max-age=0, sehingga browser tidak dipaksa selalu memakai HTTPS.',
        'impact_description' => 'Pengguna berpotensi mengakses layanan melalui koneksi yang tidak dipaksakan menggunakan HTTPS.',
        'recommendation' => 'Tambahkan header Strict-Transport-Security dengan max-age minimal 31536000 pada respons HTTPS.',
        'output' => 'Header HSTS aktif pada seluruh respons HTTPS.',
        'additional_control' => 'Periksa konfigurasi header keamanan setiap kali ada perubahan server atau aplikasi.',
    ],

    'missing-csp' => $misconfig + [
        'title' => 'Content-Security-Policy tidak diterapkan',
        'severity' => 'low',
        'impact' => 2,
        'likelihood' => 2,
        'description' => 'Tidak ditemukan header atau tag meta Content-Security-Policy. CSP membatasi sumber script dan konten sehingga mengurangi dampak serangan XSS.',
        'impact_description' => 'Jika terdapat celah XSS, script berbahaya lebih mudah dijalankan pada browser pengguna.',
        'recommendation' => 'Terapkan header Content-Security-Policy yang membatasi sumber script, style, dan frame sesuai kebutuhan aplikasi.',
        'output' => 'Header Content-Security-Policy aktif dan sesuai kebutuhan aplikasi.',
        'additional_control' => 'Uji kebijakan CSP dalam mode report-only sebelum diberlakukan penuh.',
    ],

    'missing-x-frame-options' => $misconfig + [
        'title' => 'Perlindungan clickjacking tidak diterapkan',
        'severity' => 'low',
        'impact' => 2,
        'likelihood' => 2,
        'description' => 'Tidak ada header X-Frame-Options bernilai DENY/SAMEORIGIN dan tidak ada direktif frame-ancestors pada CSP, sehingga halaman dapat dimuat di dalam frame situs lain.',
        'impact_description' => 'Halaman berpotensi disisipkan ke situs lain untuk mengelabui pengguna (clickjacking).',
        'recommendation' => 'Tambahkan header X-Frame-Options: SAMEORIGIN atau direktif CSP frame-ancestors \'self\'.',
        'output' => 'Halaman tidak dapat dimuat di dalam frame situs lain.',
        'additional_control' => 'Periksa konfigurasi header keamanan secara berkala.',
    ],

    'missing-x-content-type-options' => $misconfig + [
        'title' => 'Header X-Content-Type-Options tidak diterapkan',
        'severity' => 'info',
        'impact' => 1,
        'likelihood' => 2,
        'description' => 'Header X-Content-Type-Options tidak ada atau nilainya bukan nosniff, sehingga browser dapat menebak jenis konten.',
        'impact_description' => 'Browser berpotensi menafsirkan file dengan jenis yang salah sehingga membuka peluang eksekusi konten yang tidak diharapkan.',
        'recommendation' => 'Tambahkan header X-Content-Type-Options: nosniff.',
        'output' => 'Header X-Content-Type-Options bernilai nosniff pada seluruh respons.',
        'additional_control' => 'Periksa konfigurasi header keamanan secara berkala.',
    ],

    'missing-referrer-policy' => $misconfig + [
        'title' => 'Referrer-Policy tidak diterapkan',
        'severity' => 'info',
        'impact' => 1,
        'likelihood' => 1,
        'description' => 'Tidak ada header Referrer-Policy maupun tag meta referrer, sehingga alamat halaman dapat terkirim ke situs lain melalui header Referer.',
        'impact_description' => 'Alamat halaman beserta parameternya berpotensi terkirim ke pihak ketiga.',
        'recommendation' => 'Tambahkan header Referrer-Policy: strict-origin-when-cross-origin.',
        'output' => 'Header Referrer-Policy aktif pada seluruh respons.',
        'additional_control' => 'Periksa konfigurasi header keamanan secara berkala.',
    ],

    'insecure-cookie' => [
        'category' => 'Ketidaksesuaian Pengelolaan Aplikasi',
        'threat' => 'Penyalahgunaan aplikasi oleh pihak yang tidak berwenang',
        'vulnerability' => 'Adanya miss konfigurasi pada aplikasi',
        'impact_area' => 'Operasional dan Aset TIK',
        'title' => 'Atribut keamanan cookie tidak lengkap',
        'severity' => 'medium',
        'impact' => 2,
        'likelihood' => 2,
        'description' => 'Ditemukan cookie tanpa atribut Secure, atau cookie sesi tanpa HttpOnly atau SameSite.',
        'impact_description' => 'Cookie sesi pengguna berpotensi dicuri atau disalahgunakan untuk mengambil alih sesi.',
        'recommendation' => 'Set atribut Secure pada seluruh cookie, serta HttpOnly dan SameSite pada cookie sesi.',
        'output' => 'Seluruh cookie memiliki atribut keamanan yang sesuai.',
        'additional_control' => 'Tinjau konfigurasi sesi aplikasi setiap kali ada pembaruan framework.',
    ],

    'tls-cert-invalid' => [
        'category' => 'Terganggunya Keberlangsungan Layanan',
        'threat' => 'Kegagalan fungsi pada aplikasi',
        'vulnerability' => 'Kurangnya maintenance terhadap aplikasi secara berkala',
        'impact_area' => 'Layanan Organisasi',
        'title' => 'Sertifikat TLS tidak valid',
        'severity' => 'high',
        'impact' => 3,
        'likelihood' => 5,
        'description' => 'Verifikasi sertifikat TLS gagal karena sertifikat kedaluwarsa, belum berlaku, nama host tidak cocok, atau self-signed.',
        'impact_description' => 'Browser menampilkan peringatan keamanan sehingga layanan sulit diakses dan pengguna terbiasa mengabaikan peringatan.',
        'recommendation' => 'Pasang sertifikat TLS yang valid dari CA tepercaya dengan nama host yang sesuai.',
        'output' => 'Sertifikat TLS valid dan dipercaya browser.',
        'additional_control' => 'Gunakan perpanjangan sertifikat otomatis dan pemantauan masa berlaku.',
    ],

    'tls-chain-incomplete' => [
        'category' => 'Terganggunya Keberlangsungan Layanan',
        'threat' => 'Kegagalan fungsi pada aplikasi',
        'vulnerability' => 'Adanya miss konfigurasi pada aplikasi',
        'impact_area' => 'Layanan Organisasi',
        'title' => 'Rantai sertifikat TLS tidak lengkap',
        'severity' => 'medium',
        'impact' => 2,
        'likelihood' => 3,
        'description' => 'Server tidak mengirim sertifikat penerbit (intermediate), atau penerbit sertifikat tidak dikenali.',
        'impact_description' => 'Sebagian browser dan aplikasi gagal memverifikasi sertifikat sehingga layanan tidak dapat diakses oleh sebagian pengguna.',
        'recommendation' => 'Konfigurasikan server agar mengirim sertifikat lengkap (fullchain) termasuk intermediate.',
        'output' => 'Rantai sertifikat lengkap dan terverifikasi.',
        'additional_control' => 'Uji konfigurasi TLS setiap kali sertifikat diperbarui.',
    ],

    'tls-cert-expiring' => [
        'category' => 'Terganggunya Keberlangsungan Layanan',
        'threat' => 'Kegagalan fungsi pada aplikasi',
        'vulnerability' => 'Kurangnya maintenance terhadap aplikasi secara berkala',
        'impact_area' => 'Layanan Organisasi',
        'title' => 'Sertifikat TLS segera kedaluwarsa',
        'severity' => 'medium',
        'impact' => 3,
        'likelihood' => 3,
        'description' => 'Sertifikat TLS masih valid tetapi sisa masa berlakunya 30 hari atau kurang.',
        'impact_description' => 'Jika tidak diperpanjang, layanan akan menampilkan peringatan keamanan dan sulit diakses.',
        'recommendation' => 'Segera perpanjang sertifikat TLS sebelum masa berlakunya habis.',
        'output' => 'Sertifikat TLS diperpanjang dan masa berlakunya aman.',
        'additional_control' => 'Gunakan perpanjangan sertifikat otomatis dan pengingat masa berlaku.',
    ],

    'tls-legacy-protocol' => $infra + [
        'title' => 'Protokol TLS lama masih diterima',
        'severity' => 'medium',
        'impact' => 2,
        'likelihood' => 2,
        'description' => 'Server masih menerima koneksi TLS 1.0 atau TLS 1.1 yang sudah tidak dianggap aman.',
        'impact_description' => 'Komunikasi terenkripsi berpotensi memiliki tingkat perlindungan yang tidak memadai.',
        'recommendation' => 'Nonaktifkan TLS 1.0 dan TLS 1.1, gunakan minimal TLS 1.2.',
        'output' => 'Server hanya menerima TLS 1.2 dan TLS 1.3.',
        'additional_control' => 'Lakukan pemeriksaan konfigurasi TLS secara berkala.',
    ],

    'tls-weak-cipher' => $infra + [
        'title' => 'Cipher TLS lemah masih diterima',
        'severity' => 'medium',
        'impact' => 2,
        'likelihood' => 2,
        'description' => 'Server masih menerima cipher suite yang lemah (contoh: NULL, EXPORT, RC4, 3DES).',
        'impact_description' => 'Komunikasi terenkripsi berpotensi memiliki tingkat perlindungan yang tidak memadai.',
        'recommendation' => 'Nonaktifkan cipher lama dan gunakan cipher suite modern.',
        'output' => 'Server hanya menerima cipher suite yang kuat.',
        'additional_control' => 'Lakukan pemeriksaan konfigurasi TLS secara berkala.',
    ],

    'server-version-disclosure' => $misconfig + [
        'title' => 'Versi software server terlihat',
        'severity' => 'info',
        'impact' => 1,
        'likelihood' => 2,
        'description' => 'Header Server atau X-Powered-By menampilkan nomor versi software, sehingga memudahkan penyerang mencari kerawanan yang cocok.',
        'impact_description' => 'Informasi versi software membantu penyerang memilih kerawanan yang dapat dimanfaatkan.',
        'recommendation' => 'Sembunyikan nomor versi pada header Server dan X-Powered-By (contoh: server_tokens off, expose_php Off).',
        'output' => 'Header respons tidak lagi menampilkan versi software.',
        'additional_control' => 'Perbarui software server secara berkala.',
    ],

    'directory-listing' => $misconfig + [
        'title' => 'Directory listing aktif',
        'severity' => 'medium',
        'impact' => 2,
        'likelihood' => 5,
        'description' => 'Server menampilkan daftar isi direktori sehingga file yang tidak dimaksudkan untuk publik dapat ditemukan.',
        'impact_description' => 'File internal atau cadangan berpotensi ditemukan dan diunduh oleh siapa pun.',
        'recommendation' => 'Nonaktifkan directory listing pada web server (contoh: Options -Indexes, autoindex off).',
        'output' => 'Directory listing nonaktif pada seluruh direktori.',
        'additional_control' => 'Tinjau isi direktori publik secara berkala.',
    ],

    'exposed-sensitive-file' => [
        'category' => 'Kesalahan Pengelolaan Data dan Informasi Terbatas',
        'threat' => 'Terjadi peretasan pada aplikasi',
        'vulnerability' => 'Adanya miss konfigurasi pada aplikasi',
        'impact_area' => 'Operasional dan Aset TIK',
        'title' => 'File sensitif dapat diakses publik',
        'severity' => 'high',
        'impact' => 4,
        'likelihood' => 5,
        'description' => 'File sensitif seperti .env, konfigurasi git, atau file backup dapat diunduh oleh siapa pun.',
        'impact_description' => 'Kode, konfigurasi, atau kredensial berpotensi bocor dan dipakai untuk mengambil alih sistem.',
        'recommendation' => 'Hapus atau blokir akses ke file sensitif, lalu ganti seluruh kredensial yang mungkin sudah bocor.',
        'output' => 'File sensitif tidak dapat diakses dari internet dan kredensial telah diganti.',
        'additional_control' => 'Terapkan aturan deployment yang tidak menyertakan file sensitif ke direktori publik.',
    ],

];
