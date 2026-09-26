
# Catatan Pengembangan (berlaku saat ini, mengalahkan isi blueprint di bawah jika bertentangan)

- Framework: Laravel 13, PHP 8.3
- Lingkungan pengembangan: Windows + Laragon, bukan WSL2 atau Docker
- Mode Standar membutuhkan WSL2 atau Linux karena testssl.sh dan WhatWeb tidak berjalan langsung di Windows
- Database sementara: SQLite, target akhir PostgreSQL. Jangan pakai query khusus PostgreSQL.
- Queue sementara: driver database, target akhir Redis. Tidak memakai Laravel Horizon.
- Tanpa login, dipakai satu orang secara lokal.
- Port llama-server: 8081, bukan 8080, karena 8080 dipakai OWASP ZAP.
- Lokasi program scanner disimpan di .env, tidak ditulis langsung di kode.
- Katalog finding dan aturan penilaian disimpan di file konfigurasi, bukan ditulis langsung di kode, supaya nilainya bisa diubah tanpa mengubah program.
- Urutan pengerjaan: (1) halaman input dan antrean, (2) scanner Mode Cepat, (3) halaman hasil, (4) Nuclei, (5) Risk Engine dan export Excel, (6) AI paling akhir.
- Input target boleh tanpa http:// atau https:// (contoh esakip.jemberkab.go.id), dianggap https://. Nama tanpa titik ditolak.
- SCAN_ALLOWED_DOMAINS berisi * atau kosong berarti semua domain boleh diperiksa (mengganti bagian 26). Isi daftar domain untuk membatasi. Localhost, alamat IP, dan domain yang mengarah ke IP privat tetap ditolak.
- Domain yang tidak ada di DNS (NXDOMAIN) dicatat FAIL "tidak ditemukan di DNS". Jika server DNS tidak merespons, dicatat ERROR.
- Mode Cepat dan Standar sama-sama tersedia, Standar terpilih secara bawaan. Pemeriksaan khusus Mode Standar (Port/Nmap, testssl.sh, WhatWeb, ZAP) dicatat NOT ASSESSED pada Mode Cepat supaya terlihat di Coverage.
- Informasi HTTP (bagian 3, httpx) dikerjakan pemeriksaan bawaan PHP karena koneksi harus dikunci ke IP yang sudah lolos pemeriksaan SSRF. httpx tidak dipakai.
- Profil Nuclei per mode ada di config siprika.tools.nuclei.profiles. Dengan batas 5 request per detik, semua template bertag exposure, misconfig, tech, dan ssl berjumlah sekitar 5.500 request dan tidak selesai dalam 10 menit. Karena itu Mode Cepat hanya menjalankan 10 template informasi penting ditambah tag tersebut dengan severity high dan critical (sekitar 1.000 request, sekitar 3 menit). Mode Standar menjalankan semua severity ditambah tag cve (sekitar 7.000 request, sekitar 22 menit).
- Batas waktu: Mode Cepat 10 menit, Mode Standar 45 menit per website, Nuclei 30 menit. Tool yang terpotong batas waktu dicatat ERROR, tetapi hasil yang sempat didapat tetap disimpan.
- Tool eksternal di Windows dijalankan lewat WSL Ubuntu tanpa shell, contoh NUCLEI_PATH="wsl -d Ubuntu -e nuclei".
- AI memakai llama.cpp build CPU untuk Windows (D:\tools\llama.cpp). llama-server ikut dijalankan oleh php artisan siprika:serve jika AI_SERVER_COMMAND diisi. Satu analisis sekitar 40 sampai 50 detik di CPU, hasilnya disimpan per kunci finding dan dipakai ulang.
- Setelah mengubah .env, hentikan lalu jalankan ulang php artisan siprika:serve karena queue worker memakai environment saat pertama dijalankan.
- Website di belakang Cloudflare Bot Fight Mode menyajikan halaman tantangan ke HTTP client PHP. Pemeriksaan header, cookie, dan exposure dicatat NOT ASSESSED sampai User-Agent atau IP SIPRIKA dimasukkan ke allowlist WAF. SIPRIKA tidak mengakali proteksi tersebut.

---

# SIPRIKA
Sistem Penilaian Risiko Keamanan Aplikasi

## 1. Tujuan Sistem

SIPRIKA adalah aplikasi web untuk melakukan pemeriksaan informasi dan keamanan dasar pada website secara otomatis, menganalisis hasil pemeriksaan menggunakan scanner dan model AI lokal, kemudian menghasilkan temuan keamanan serta Risk Register.

Alur utama:

```
Website → Security Scanner → Technical Evidence → AI Analysis → Risk Assessment → Risk Register → Excel
```

SIPRIKA bukan penetration testing tool dan tidak melakukan eksploitasi terhadap target.

## 2. Alur Pengguna

User membuka halaman utama SIPRIKA tanpa perlu login.

Pada halaman utama tersedia **Target Website**. User dapat memasukkan satu atau beberapa URL sekaligus. Contoh:

```
https://website-a.go.id
https://website-b.go.id
https://website-c.go.id
```

Kemudian user memilih **Mode Pemeriksaan**:

```
○ Cepat
● Standar
```

dan menekan tombol **MULAI PEMERIKSAAN**.

Jika terdapat beberapa URL, SIPRIKA membuat antrean:

```
Website A → sedang diperiksa
Website B → menunggu
Website C → menunggu
```

Setelah Website A selesai, SIPRIKA otomatis melanjutkan Website B dan seterusnya.

## 3. Mode Pemeriksaan

| Pemeriksaan | Cepat | Standar |
|---|---|---|
| Validasi URL & DNS | ✓ | ✓ |
| HTTP Status / Redirect | ✓ | ✓ |
| Title / Server / CDN / IP | ✓ | ✓ |
| Security Headers | ✓ | ✓ |
| Technology Detection | ✓ | ✓ |
| TLS Basic | ✓ | ✓ |
| TLS Lengkap | - | ✓ |
| Exposure Detection | terbatas | ✓ |
| Nuclei Safe Scan | ringan | ✓ |
| Port/Web Service Detection | - | ✓ |
| Passive Web Analysis | - | ✓ |
| AI Risk Analysis | ✓ | ✓ |
| Risk Register | ✓ | ✓ |

### Mode Cepat

Digunakan untuk memperoleh gambaran umum website dalam waktu lebih singkat.

- **httpx** (tool utama): mendeteksi HTTP status, HTTPS, title, redirect, web server, IP, CDN/WAF.
- **HTTP Security Checker**: memeriksa HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Secure Cookie, HttpOnly, SameSite.
- **Technology Detection**: mendeteksi CMS, framework, web server, JavaScript library, dan teknologi lain yang terlihat dari luar.
- **TLS Basic**: memeriksa certificate validity, masa berlaku, hostname, versi TLS dasar.
- **Nuclei Light**: hanya menjalankan template aman dan ringan seperti exposure, misconfiguration, technology detection, informational security checks.

## 4. Mode Standar

Mode Standar menjalankan seluruh pemeriksaan Mode Cepat ditambah pemeriksaan yang lebih lengkap.

Scanner yang digunakan:

- **httpx**: pemeriksaan informasi dasar website.
- **WhatWeb**: technology fingerprinting tambahan.
- **testssl.sh**: memeriksa certificate, certificate chain, TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3, weak cipher, cryptographic configuration.
- **Nuclei**: mendeteksi CVE, exposure, misconfiguration, technology vulnerability, safe vulnerability checks. Nuclei harus menggunakan profil template yang telah disetujui.
- **Nmap**: digunakan secara terbatas untuk port web, identifikasi service, dan service version jika tersedia. Tidak menggunakan aggressive exploitation.
- **OWASP ZAP** (opsional): passive scan, HTTP security analysis, passive security alerts. Tidak menjalankan active exploitation pada versi awal SIPRIKA.

## 5. Batas Pemeriksaan

SIPRIKA hanya melakukan pemeriksaan non-eksploitatif.

SIPRIKA tidak menjalankan:

- DoS
- brute force
- credential attack
- eksploitasi RCE
- eksploitasi SQL Injection
- malicious file upload
- destructive fuzzing
- perubahan data pada target
- authentication attack
- authorization exploitation
- business logic exploitation

Pemeriksaan yang tidak dapat dilakukan tanpa akun/login harus diberi status `PARTIAL` atau `NOT ASSESSED`, bukan dianggap `PASS`.

## 6. Model AI SIPRIKA

SIPRIKA menggunakan model lokal yang sudah dilatih sebelumnya:

- Model: `qwen2.5-7b-instruct.Q4_K_M.gguf`
- Format: GGUF

Model tidak perlu dilatih kembali di dalam SIPRIKA. Model digunakan hanya untuk inference. Model dijalankan secara lokal sehingga data hasil pemeriksaan tidak perlu dikirim ke layanan LLM eksternal.

### Fungsi Model

Model menerima hasil pemeriksaan yang sudah dinormalisasi. Contoh input: informasi target, hasil httpx, security headers, TLS, technology, Nuclei findings, exposure, CVE, CVSS, evidence.

Model membantu menghasilkan:

- nama finding yang lebih mudah dipahami
- deskripsi kerawanan
- ancaman
- kategori risiko
- kemungkinan dampak
- rekomendasi penanganan
- kontrol tambahan
- narasi Risk Register
- pemetaan technical finding ke Risk Register

Model tidak melakukan scanning website secara langsung.

## 7. Posisi Model Dalam Arsitektur

Pipeline SIPRIKA:

```
Target Website
↓
Scanner (httpx, WhatWeb, testssl.sh, Nuclei, Nmap, ZAP Passive)
↓
Raw Scanner Result
↓
Normalizer
↓
Technical Evidence
↓
Finding
↓
AI Risk Analyzer
↓
Risk Mapper
↓
Risk Engine
↓
Official Risk Matrix
↓
Risk Register
```

Model tidak boleh langsung menerima website dan menyatakan website aman atau tidak aman. Model hanya menganalisis evidence yang dihasilkan scanner.

## 8. Aturan Penggunaan AI

Output model harus dianggap sebagai hasil analisis, bukan fakta mentah. Evidence tetap berasal dari scanner.

Contoh: Nuclei menemukan `ssl-weak-cipher`. Kemudian AI dapat membuat:

- **Kerawanan**: Konfigurasi TLS masih mendukung algoritma kriptografi yang lemah.
- **Ancaman**: Komunikasi terenkripsi berpotensi memiliki tingkat perlindungan yang tidak memadai.
- **Rekomendasi**: Nonaktifkan cipher lemah dan gunakan cipher suite modern.

Tetapi AI tidak boleh menciptakan finding jika scanner tidak memiliki evidence yang mendukung.

## 9. AI Output Contract

Agar hasil model mudah digunakan Laravel, output AI harus berbentuk JSON terstruktur. Contoh:

```json
{
    "finding": "Konfigurasi TLS Lemah",
    "threat": "Penurunan keamanan komunikasi terenkripsi",
    "vulnerability": "Server masih mendukung cipher yang lemah",
    "category": "Keamanan Informasi",
    "impact_description": "Komunikasi pengguna berpotensi memiliki tingkat perlindungan yang tidak memadai.",
    "recommendation": "Nonaktifkan cipher lama dan gunakan konfigurasi TLS modern.",
    "additional_control": "Lakukan pemeriksaan konfigurasi TLS secara berkala."
}
```

SIPRIKA harus melakukan validasi JSON sebelum hasil AI digunakan. Jika output model tidak valid, timeout, atau gagal diproses, SIPRIKA tetap dapat menghasilkan hasil pemeriksaan teknis. Kegagalan AI tidak boleh membuat seluruh scan gagal.

## 10. Local AI Runtime

Karena model menggunakan format GGUF, runtime yang direkomendasikan adalah llama.cpp.

Arsitektur:

```
Laravel
↓
HTTP Request
↓
Local AI Service
↓
llama.cpp
↓
qwen2.5-7b-instruct.Q4_K_M.gguf
```

Model berjalan sebagai service lokal, contoh: `http://127.0.0.1:8081`

Laravel mengirim JSON hasil finding ke service model kemudian menerima JSON hasil analisis. Dengan cara ini Laravel tidak perlu menjalankan model secara langsung.

## 11. Proses Internal Scanner

Setiap scanner menghasilkan Observation. Status Observation: `PASS`, `FAIL`, `INFO`, `ERROR`, `N/A`.

Kemudian observation yang relevan diubah menjadi Finding.

```
Scanner
↓
Observation
↓
Finding Normalizer
↓
Finding
↓
Deduplication
↓
Evidence
```

Jika beberapa scanner mendeteksi masalah yang sama, SIPRIKA harus menggabungkannya. Contoh: Exposure Scanner menemukan `.env` dan Nuclei juga menemukan `.env`, maka hasilnya menjadi 1 Finding dengan 2 Evidence Sources.

## 12. Status Pemeriksaan

Setiap target memiliki status:

- `QUEUED`: menunggu antrean
- `RUNNING`: sedang diperiksa
- `COMPLETED`: pemeriksaan selesai
- `PARTIAL`: sebagian scanner gagal
- `FAILED`: target tidak dapat diperiksa
- `CANCELLED`: pemeriksaan dibatalkan

## 13. Progress Pemeriksaan

UI menampilkan progress seperti:

```
Target Validation ✓
HTTP Information ✓
Security Headers ✓
Technology Detection ✓
TLS ✓
Nuclei Running...
AI Analysis Waiting...
Risk Assessment Waiting...
Risk Register Waiting...
```

Jika salah satu scanner gagal, scanner lainnya tetap dilanjutkan.

## 14. Hasil Pemeriksaan

Setelah pemeriksaan selesai tersedia empat bagian utama.

### Overview
Menampilkan: URL, IP Address, HTTP Status, HTTPS, Title, Web Server, CDN/WAF, Technology, CMS, TLS, waktu pemeriksaan.

### Security Check
Menampilkan: HTTPS, HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Cookie Security, TLS, Certificate, Exposure, Technology Vulnerability.

### Findings
Setiap finding minimal memiliki: nama finding, deskripsi, URL/endpoint, severity teknis, scanner sumber, evidence, CVE jika tersedia, CVSS jika tersedia, rekomendasi.

### Risk Register
Menampilkan hasil pemetaan risiko berdasarkan finding.

## 15. Risk Engine

Scanner dan model AI tidak langsung menentukan nilai akhir risiko. Risk Engine menentukan:

Impact:
- 1: Tidak Signifikan
- 2: Kurang Signifikan
- 3: Cukup Signifikan
- 4: Signifikan
- 5: Sangat Signifikan

Likelihood:
- 1: Hampir Tidak Terjadi
- 2: Jarang Terjadi
- 3: Kadang-Kadang Terjadi
- 4: Sering Terjadi
- 5: Hampir Pasti Terjadi

Nilai risiko menggunakan matriks pada template Risk Register. Tidak menggunakan Impact × Likelihood jika template resmi menggunakan matrix lookup.

Data seperti CVSS, CVE, Nuclei Severity, EPSS, CISA KEV, dan hasil AI merupakan supporting evidence.

## 16. Risk Register

Finding dari scanner kemudian dipetakan menjadi Risk Register. Contoh:

```
Finding
HSTS tidak diterapkan
↓
AI Analysis
↓
Kerawanan
Konfigurasi HTTPS belum menerapkan HTTP Strict Transport Security.
↓
Ancaman
Pengguna berpotensi mengakses layanan melalui koneksi yang tidak dipaksakan menggunakan HTTPS.
↓
Risk Engine
↓
Risk Register
```

## 17. Excel Risk Register

SIPRIKA menggunakan file template Risk Register yang diberikan sebagai template utama. SIPRIKA hanya perlu mengisi sheet **Perangkat Lunak** (ASET: PERANGKAT LUNAK). Setiap risiko unik per website menjadi satu baris Risk Register. Sumber isi setiap kolom dijelaskan di bagian 25.

Kolom yang tidak dapat diketahui dari pemeriksaan teknis seperti Kontrol Saat Ini, Target/Jadwal Implementasi, Penanggung Jawab, Residual Risk, dan Risk Owner tidak boleh dibuat-buat oleh AI maupun sistem. Kolom tersebut dibiarkan kosong untuk diisi user.

SIPRIKA harus mempertahankan: format template, formula, dropdown, Risk Matrix, sheet Ringkasan, dan sheet pendukung.

## 18. Functional Requirement

- **FR-01 Input Target**: Sistem menerima satu atau beberapa URL.
- **FR-02 Target Validation**: Melakukan normalisasi URL, DNS validation, redirect validation, dan SSRF protection.
- **FR-03 Scan Mode**: User dapat memilih Cepat atau Standar.
- **FR-04 Queue**: Beberapa website diproses menggunakan antrean.
- **FR-05 Scanner Integration**: SIPRIKA dapat menjalankan dan membaca output httpx, testssl.sh, Nuclei, WhatWeb, Nmap, ZAP Passive.
- **FR-06 Finding Normalization**: Output scanner diubah menjadi struktur finding yang sama.
- **FR-07 Deduplication**: Finding yang sama dari beberapa scanner digabung.
- **FR-08 AI Analysis**: Finding dikirim ke model lokal untuk membantu menghasilkan analisis risiko terstruktur.
- **FR-09 AI Validation**: Output model harus divalidasi sebelum digunakan.
- **FR-10 Risk Engine**: Sistem menghitung risiko menggunakan aturan dan Risk Matrix.
- **FR-11 Result**: User dapat melihat informasi website, finding, evidence, coverage, dan Risk Register.
- **FR-12 Excel Export**: Risk Register dapat diekspor ke template Excel yang diberikan.

## 19. Tech Stack

- **Backend**: Laravel / PHP
- **Frontend**: Blade + Tailwind CSS + Alpine.js
- **Database**: PostgreSQL
- **Queue**: Laravel Queue + Redis
- **Scanner**: httpx, Nuclei, testssl.sh, WhatWeb, Nmap, OWASP ZAP Passive
- **AI**: model qwen2.5-7b-instruct.Q4_K_M.gguf, runtime llama.cpp, mode local inference. Tidak membutuhkan API LLM eksternal.
- **Reporting**: PhpSpreadsheet untuk menghasilkan file Excel Risk Register.
- **Deployment versi awal**: Windows + WSL2 / Linux, atau Docker.

## 20. Sistem Utama

```
USER
↓
SIPRIKA WEB UI
↓
TARGET QUEUE
↓
SCANNER ORCHESTRATOR
↓
httpx / WhatWeb / testssl / Nuclei / Nmap / ZAP Passive
↓
OBSERVATION
↓
FINDING + EVIDENCE
↓
LOCAL AI MODEL (Qwen2.5 7B SIPRIKA Model)
↓
RISK MAPPER
↓
RISK ENGINE
↓
RISK REGISTER
↓
EXCEL
```

## 21. Definition of Done

SIPRIKA versi pertama dianggap berhasil apabila user dapat menjalankan alur:

```
Masukkan URL
↓
Pilih Cepat / Standar
↓
Mulai
↓
Scanner berjalan
↓
Finding ditemukan
↓
Model menganalisis Finding
↓
Risk Engine menilai risiko
↓
Hasil ditampilkan
↓
Risk Register dibuat
↓
Excel dapat diunduh
```

Untuk banyak website:

```
Masukkan beberapa URL
↓
Queue
↓
Website diperiksa satu per satu
↓
Hasil setiap website tersimpan
↓
Risk Register digabungkan
↓
Export Excel
```

Prinsip utama SIPRIKA:

- Scanner menentukan apa yang ditemukan.
- AI membantu memahami dan memetakan temuan.
- Risk Engine menentukan risiko berdasarkan aturan.
- Tidak ditemukan vulnerability tidak berarti website sepenuhnya aman.

## 22. Aturan Akurasi Pemeriksaan

1. Pemeriksaan header dan cookie memakai respons halaman utama setelah mengikuti redirect, maksimal 5 langkah. URL final dicatat.
2. Status `FAIL` hanya diberikan jika kondisi terbukti dari respons. Timeout, koneksi terputus, atau error tool dicatat `ERROR`, tidak pernah `FAIL` maupun `PASS`.
3. Permintaan yang gagal karena jaringan diulang satu kali sebelum dicatat `ERROR`.
4. Jika respons berupa halaman blokir WAF/CDN (status 403, 429, atau 503 dari penyedia WAF), pemeriksaan header dan cookie diberi status `NOT ASSESSED`, karena yang terbaca adalah WAF, bukan website aslinya.
5. Verifikasi sertifikat memakai CA bundle terbaru (pengaturan `curl.cainfo` dan `openssl.cafile` di php.ini). Tanpa CA bundle, semua sertifikat akan terbaca tidak valid. Sebelum dipakai, pemeriksaan TLS diuji ke website dengan sertifikat valid yang sudah diketahui.
6. Setiap observation menyimpan nilai mentah yang menjadi dasar keputusan: nama dan nilai header, atribut cookie, tanggal berlaku sertifikat, pesan error verifikasi. Dengan begitu setiap temuan bisa dicek ulang.
7. Pemeriksaan yang tidak dapat dilakukan oleh tool yang tersedia diberi status `NOT ASSESSED`, bukan `PASS`.
8. Coverage adalah daftar semua pemeriksaan beserta statusnya (`PASS`, `FAIL`, `ERROR`, `NOT ASSESSED`) untuk setiap website, dan ditampilkan di halaman hasil. Mode Cepat hanya memeriksa halaman utama, dan batasan ini ditampilkan di Coverage.
9. Semua permintaan memakai User-Agent tetap, contoh: `SIPRIKA/1.0 (Diskominfo Jember)`, supaya admin website dapat mengenali pemeriksaan.

## 23. Katalog Finding Mode Cepat

Setiap finding punya kunci tetap. Kunci ini dipakai untuk deduplikasi, penilaian risiko, dan penyimpanan hasil AI. Hasil dari scanner mana pun yang maknanya sama dipetakan ke kunci yang sama. Contoh: pengecekan header internal dan template Nuclei `http-missing-security-headers` bagian strict-transport-security sama-sama menjadi `missing-hsts`.

### 23.1 Kriteria Deteksi

| Kunci | Terdeteksi jika | Catatan akurasi |
|---|---|---|
| `no-https` | Port 443 menolak koneksi atau handshake TLS gagal, sementara http:// merespons normal | Timeout dicatat `ERROR`, bukan temuan. Handshake berhasil tapi sertifikat bermasalah masuk kunci sertifikat |
| `http-not-redirected` | http:// merespons 2xx tanpa redirect 301, 302, 307, atau 308 ke https:// | Port 80 tertutup bukan temuan. Redirect bertahap yang berakhir di https:// dihitung redirect |
| `missing-hsts` | Respons HTTPS final tidak memiliki header Strict-Transport-Security, atau max-age=0 | Header HSTS pada respons HTTP diabaikan. Nilai max-age dicatat di evidence |
| `missing-csp` | Tidak ada header Content-Security-Policy dan tidak ada tag meta http-equiv Content-Security-Policy | Header Content-Security-Policy-Report-Only saja tetap dihitung tidak ada, dicatat di evidence |
| `missing-x-frame-options` | Tidak ada X-Frame-Options bernilai DENY atau SAMEORIGIN, dan tidak ada direktif frame-ancestors di header CSP | frame-ancestors di tag meta tidak dihitung karena diabaikan browser. Nilai ALLOW-FROM dianggap tidak ada |
| `missing-x-content-type-options` | Header X-Content-Type-Options tidak ada atau nilainya bukan nosniff | - |
| `missing-referrer-policy` | Tidak ada header Referrer-Policy dan tidak ada tag meta referrer | - |
| `insecure-cookie` | Pada respons HTTPS: ada cookie tanpa Secure, atau cookie sesi tanpa HttpOnly, atau cookie sesi tanpa SameSite | Cookie yang memang dibaca JavaScript (contoh: XSRF-TOKEN) tidak diperiksa HttpOnly. Cookie sesi dikenali dari nama: session, sess, sid, PHPSESSID, JSESSIONID, ASP.NET_SessionId, laravel_session, ci_session, wordpress_logged_in |
| `tls-cert-invalid` | Verifikasi gagal karena sertifikat kedaluwarsa, belum berlaku, hostname tidak cocok, atau self-signed | Alasan kegagalan dari OpenSSL disimpan di evidence |
| `tls-chain-incomplete` | Verifikasi gagal karena sertifikat penerbit (intermediate) tidak dikirim server atau penerbit tidak dikenali | Sebagian browser tetap bisa membuka website. Dikonfirmasi di Mode Standar dengan testssl.sh |
| `tls-cert-expiring` | Sertifikat valid, sisa masa berlaku 30 hari atau kurang, dan kurang dari 1/4 total masa berlakunya | Aturan 1/4 mencegah sertifikat yang diperbarui otomatis (misalnya Let's Encrypt) dianggap temuan |
| `tls-legacy-protocol` | Server menerima TLS 1.0 atau TLS 1.1 (Nuclei tag ssl atau testssl.sh) | Jika tool tidak mampu menguji TLS 1.0/1.1, status `NOT ASSESSED` |
| `server-version-disclosure` | Header Server atau X-Powered-By memuat nomor versi, contoh: Apache/2.4.41, PHP/8.1.2 | Nama software tanpa versi (contoh: nginx) bukan temuan |
| `directory-listing` | Template Nuclei directory listing cocok berdasarkan isi halaman | - |
| `exposed-sensitive-file` | Template Nuclei exposure cocok berdasarkan isi file, contoh: .env, .git/config, file backup | Status 200 saja tidak cukup. Evidence hanya menyimpan nama file dan potongan isi maksimal 200 karakter, dengan nilai rahasia disamarkan |

### 23.2 Klasifikasi

Kolom Kategori mengikuti sheet List Kategori Risiko Keamanan. Kolom Ancaman dan Kerawanan mengikuti sheet List Ancaman dan Kerentanan untuk aset Perangkat Lunak.

| Kunci | Kategori | Ancaman | Kerawanan | Area Dampak |
|---|---|---|---|---|
| `no-https` | Keamanan Infrastruktur | Terjadi peretasan pada aplikasi | Lemahnya mekanisme kriptografi aplikasi | Operasional dan Aset TIK |
| `http-not-redirected` | Keamanan Infrastruktur | Terjadi peretasan pada aplikasi | Lemahnya mekanisme kriptografi aplikasi | Operasional dan Aset TIK |
| `missing-hsts` | Keamanan Infrastruktur | Terjadi peretasan pada aplikasi | Lemahnya mekanisme kriptografi aplikasi | Operasional dan Aset TIK |
| `missing-csp` | Ketidaksesuaian Pengelolaan Aplikasi | Terjadi peretasan pada aplikasi | Adanya miss konfigurasi pada aplikasi | Operasional dan Aset TIK |
| `missing-x-frame-options` | Ketidaksesuaian Pengelolaan Aplikasi | Terjadi peretasan pada aplikasi | Adanya miss konfigurasi pada aplikasi | Operasional dan Aset TIK |
| `missing-x-content-type-options` | Ketidaksesuaian Pengelolaan Aplikasi | Terjadi peretasan pada aplikasi | Adanya miss konfigurasi pada aplikasi | Operasional dan Aset TIK |
| `missing-referrer-policy` | Ketidaksesuaian Pengelolaan Aplikasi | Terjadi peretasan pada aplikasi | Adanya miss konfigurasi pada aplikasi | Operasional dan Aset TIK |
| `insecure-cookie` | Ketidaksesuaian Pengelolaan Aplikasi | Penyalahgunaan aplikasi oleh pihak yang tidak berwenang | Adanya miss konfigurasi pada aplikasi | Operasional dan Aset TIK |
| `tls-cert-invalid` | Terganggunya Keberlangsungan Layanan | Kegagalan fungsi pada aplikasi | Kurangnya maintenance terhadap aplikasi secara berkala | Layanan Organisasi |
| `tls-chain-incomplete` | Terganggunya Keberlangsungan Layanan | Kegagalan fungsi pada aplikasi | Adanya miss konfigurasi pada aplikasi | Layanan Organisasi |
| `tls-cert-expiring` | Terganggunya Keberlangsungan Layanan | Kegagalan fungsi pada aplikasi | Kurangnya maintenance terhadap aplikasi secara berkala | Layanan Organisasi |
| `tls-legacy-protocol` | Keamanan Infrastruktur | Terjadi peretasan pada aplikasi | Lemahnya mekanisme kriptografi aplikasi | Operasional dan Aset TIK |
| `server-version-disclosure` | Ketidaksesuaian Pengelolaan Aplikasi | Terjadi peretasan pada aplikasi | Adanya miss konfigurasi pada aplikasi | Operasional dan Aset TIK |
| `directory-listing` | Ketidaksesuaian Pengelolaan Aplikasi | Terjadi peretasan pada aplikasi | Adanya miss konfigurasi pada aplikasi | Operasional dan Aset TIK |
| `exposed-sensitive-file` | Kesalahan Pengelolaan Data dan Informasi Terbatas | Terjadi peretasan pada aplikasi | Adanya miss konfigurasi pada aplikasi | Operasional dan Aset TIK |

Detail dari evidence ditambahkan di akhir kolom Kerawanan. Contoh: "Lemahnya mekanisme kriptografi aplikasi (header Strict-Transport-Security tidak ditemukan pada respons HTTPS)".

## 24. Aturan Penilaian Risiko

### 24.1 Kemungkinan

Template mendefinisikan Kemungkinan berdasarkan frekuensi kejadian per tahun, yang tidak dapat diukur dari pemindaian. SIPRIKA menilai berdasarkan kemudahan kerawanan dimanfaatkan:

| Nilai | Label | Kondisi |
|---|---|---|
| 5 | Hampir Pasti Terjadi | Kondisi sudah terjadi atau dapat dimanfaatkan siapa pun tanpa syarat, atau CVE masuk daftar CISA KEV |
| 4 | Sering Terjadi | Dapat dimanfaatkan dari internet dengan alat umum tanpa posisi khusus |
| 3 | Kadang-Kadang Terjadi | Dapat dimanfaatkan jika ada kondisi tambahan yang wajar |
| 2 | Jarang Terjadi | Butuh posisi khusus (penyerang di jaringan yang sama) atau kerawanan lain terlebih dahulu |
| 1 | Hampir Tidak Terjadi | Hanya penguatan konfigurasi, tidak ada skenario serangan langsung |

### 24.2 Dampak

Mengacu pada kolom Operasional TIK dan Layanan Organisasi di sheet Peta Risiko:

| Nilai | Label | Kondisi |
|---|---|---|
| 1 | Tidak Signifikan | Kebocoran informasi teknis ringan, layanan tidak terganggu |
| 2 | Kurang Signifikan | Melemahkan lapisan perlindungan, dampak terbatas |
| 3 | Cukup Signifikan | Layanan terganggu, atau data sesi/login pengguna dapat disadap |
| 4 | Signifikan | Pengambilalihan sebagian sistem, defacement, atau kebocoran kode/konfigurasi |
| 5 | Sangat Signifikan | Pengambilalihan penuh atau kebocoran data pribadi dalam jumlah besar |

### 24.3 Penilaian per Finding

IR dan Level dihitung dengan tabel RiskMatrix dan RiskLevel di sheet Peta Risiko, sama seperti rumus Excel. Status mengikuti rumus template: IR 11 ke atas adalah Not Acceptable.

| Kunci | Dampak | Kemungkinan | IR | Level | Status |
|---|---|---|---|---|---|
| `no-https` | 3 Cukup Signifikan | 2 Jarang Terjadi | 11 | Sedang | Not Acceptable |
| `http-not-redirected` | 2 Kurang Signifikan | 2 Jarang Terjadi | 7 | Rendah | Acceptable |
| `missing-hsts` | 2 Kurang Signifikan | 2 Jarang Terjadi | 7 | Rendah | Acceptable |
| `missing-csp` | 2 Kurang Signifikan | 2 Jarang Terjadi | 7 | Rendah | Acceptable |
| `missing-x-frame-options` | 2 Kurang Signifikan | 2 Jarang Terjadi | 7 | Rendah | Acceptable |
| `missing-x-content-type-options` | 1 Tidak Signifikan | 2 Jarang Terjadi | 2 | Sangat Rendah | Acceptable |
| `missing-referrer-policy` | 1 Tidak Signifikan | 1 Hampir Tidak Terjadi | 1 | Sangat Rendah | Acceptable |
| `insecure-cookie` | 2 Kurang Signifikan | 2 Jarang Terjadi | 7 | Rendah | Acceptable |
| `tls-cert-invalid` | 3 Cukup Signifikan | 5 Hampir Pasti Terjadi | 18 | Tinggi | Not Acceptable |
| `tls-chain-incomplete` | 2 Kurang Signifikan | 3 Kadang-Kadang Terjadi | 10 | Rendah | Acceptable |
| `tls-cert-expiring` | 3 Cukup Signifikan | 3 Kadang-Kadang Terjadi | 14 | Sedang | Not Acceptable |
| `tls-legacy-protocol` | 2 Kurang Signifikan | 2 Jarang Terjadi | 7 | Rendah | Acceptable |
| `server-version-disclosure` | 1 Tidak Signifikan | 2 Jarang Terjadi | 2 | Sangat Rendah | Acceptable |
| `directory-listing` | 2 Kurang Signifikan | 5 Hampir Pasti Terjadi | 15 | Sedang | Not Acceptable |
| `exposed-sensitive-file` | 4 Signifikan | 5 Hampir Pasti Terjadi | 23 | Sangat Tinggi | Not Acceptable |

### 24.4 Finding Nuclei di Luar Katalog

- Kunci: `nuclei:<template-id>`.
- Dampak dari severity Nuclei: critical = 5, high = 4, medium = 3, low = 2. Severity info tidak menjadi baris Risk Register, hanya tampil di tab Findings.
- Kemungkinan: 5 jika CVE masuk daftar CISA KEV (jika data tersedia), selain itu 3.
- Kategori: Ketidaksesuaian Pengelolaan Aplikasi. Ancaman: Terjadi peretasan pada aplikasi. Kerawanan: "Aplikasi tidak update" jika ada CVE, selain itu "Adanya miss konfigurasi pada aplikasi".

### 24.5 Aturan Umum

- Observation berstatus `PASS`, `INFO`, `N/A`, `ERROR`, dan `NOT ASSESSED` tidak menjadi baris Risk Register.
- Satu baris Risk Register adalah satu website dengan satu kunci finding. Jika finding yang sama muncul di beberapa endpoint pada website yang sama, endpoint digabung sebagai evidence dalam baris yang sama.

## 25. Pengisian Kolom Risk Register (sheet Perangkat Lunak)

| Kolom | Isi | Sumber |
|---|---|---|
| A Risk No | PL-001, PL-002, dan seterusnya | Sistem |
| B Jenis Risiko | Selalu "Negatif" | Sistem |
| C Aset | Nama website dan domain, contoh: "Website Dinas X (dinasx.jemberkab.go.id)" | Hasil httpx |
| D Ancaman | Dari katalog | Katalog |
| E Kerawanan | Dari katalog ditambah detail evidence | Katalog dan evidence |
| F Kategori | Dari katalog, harus salah satu dari 12 kategori di template | Katalog |
| G Dampak (deskriptif) | Kalimat dampak | AI, cadangan teks katalog |
| H Area Dampak | Dari katalog, harus nilai dropdown | Katalog |
| I Kontrol Saat Ini | Dikosongkan | User |
| J Dampak, K Kemungkinan | Label sesuai dropdown | Risk Engine |
| L IR, M Level Risiko | Tidak ditulis, dihitung rumus template | Rumus Excel |
| N Keputusan Penanganan | "Ya" jika Not Acceptable, selain itu kosong | Risk Engine |
| O Prioritas Risiko | Urutan IR tertinggi per website, 1 adalah tertinggi | Risk Engine |
| P Opsi Penanganan | "Mitigasi Risiko" jika Not Acceptable, selain itu kosong | Risk Engine |
| Q Rencana Aksi | Rekomendasi penanganan | AI, cadangan teks katalog |
| R Keluaran | Hasil yang diharapkan setelah ditangani | Katalog |
| S Target/Jadwal, T Penanggung Jawab | Dikosongkan | User |
| U, V, W Residual Risk | Dikosongkan | User |
| X, Y, dan kolom AB sampai AI | Tidak ditulis, dihitung rumus template | Rumus Excel |
| Z Rencana Kontrol Tambahan | Kontrol tambahan | AI, cadangan teks katalog |
| AA Risk Owner | Dikosongkan | User |

## 26. Batas Pemindaian

## 26. Batas Pemindaian

- Daftar domain yang boleh dipindai diatur lewat `SCAN_ALLOWED_DOMAINS` di `.env`. Beberapa domain dipisah koma, contoh: `SCAN_ALLOWED_DOMAINS=jemberkab.go.id`. Subdomain dari domain tersebut ikut diizinkan. URL di luar daftar ditolak saat input.
- Jika `SCAN_ALLOWED_DOMAINS` kosong atau bernilai `*`, semua domain diizinkan. Pengguna bertanggung jawab memastikan setiap website yang diperiksa sudah mendapat izin.
- URL berupa alamat IP (IPv4 maupun IPv6) dan localhost ditolak saat input.
- Saat pemeriksaan, domain yang mengarah ke IP privat dihentikan sebelum ada permintaan HTTP (perlindungan SSRF). Redirect ke domain lain tidak diikuti.
- Satu website diperiksa dalam satu waktu, sesuai urutan antrean.
- Kecepatan Nuclei maksimal 5 request per detik per website.
- Setiap tool punya batas waktu sendiri. Mode Cepat maksimal 10 menit per website. Tool yang melewati batas waktu dicatat `ERROR`, dan website diberi status `PARTIAL`.
- Profil Nuclei Mode Cepat hanya memakai tag exposure, misconfig, tech, dan ssl.
- Semua mode wajib mengecualikan template bertag intrusive, dos, fuzz, default-login, dan template lain yang mencoba login atau menebak kredensial.
- Setiap pemeriksaan dicatat: waktu, target, mode, dan tool yang dijalankan.

## 27. Aturan Tambahan AI

- AI hanya menerima JSON finding hasil normalizer, tidak pernah URL atau hasil mentah scanner.
- Setiap nomor CVE, versi software, dan URL di jawaban AI harus ada di data input. Jika tidak, jawaban ditolak dan dipakai teks cadangan dari katalog.
- Hasil AI disimpan per kunci finding dan dipakai ulang untuk website lain dengan finding yang sama.
- Batas waktu satu permintaan AI adalah 60 detik. Lewat batas waktu, dipakai teks cadangan.
- Teks yang berasal dari AI ditandai di database, supaya dapat dibedakan dari teks katalog.

## 28. Aturan Export Excel

- Data ditulis ke sheet Perangkat Lunak mulai baris 7. Baris contoh bawaan template (PL-001, PL-002) dihapus sebelum diisi.
- Rumus dan dropdown di template hanya tersedia di baris 7 sampai 11. Export wajib menyalin format, rumus (kolom L, M, X, Y, AB, AC, AF, AG, AH), dan dropdown ke setiap baris baru, serta memperluas rumus SUM di baris total.
- Kolom yang berisi rumus tidak ditulis nilainya oleh SIPRIKA.
- Dropdown Kategori mengambil daftar dari sheet List Kategori Risiko Keamanan dan wajib tetap berfungsi setelah export.
- Sheet selain Perangkat Lunak tidak diubah.
- Setiap perubahan kode export diuji dengan membuka file hasilnya di Microsoft Excel: tidak ada pesan error, rumus terhitung, dan dropdown berfungsi.

## 29. Definition of Done MVP

- Mode Cepat berjalan untuk banyak URL melalui antrean.
- Finding dan evidence tersimpan, deduplikasi per website per kunci finding berjalan.
- Risk Engine menilai risiko memakai aturan di bagian 24 dan matriks template.
- Halaman hasil menampilkan Overview, Security Check, Findings, Risk Register, dan Coverage.
- Export ke template Excel sheet Perangkat Lunak dengan rumus dan dropdown tetap berfungsi.
- AI tidak wajib. Jika AI tidak aktif, kolom deskriptif diisi teks katalog.

Mode Standar dan integrasi AI termasuk Definition of Done lengkap di bagian 21.