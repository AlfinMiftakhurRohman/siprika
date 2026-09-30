# SIPRIKA

Sistem Penilaian Risiko Keamanan Aplikasi. SIPRIKA memeriksa keamanan dasar website secara otomatis dan non-eksploitatif, lalu menyusun temuan menjadi Risk Register sesuai template Excel (sheet Perangkat Lunak).

```
Website → Scanner → Observation → Finding + Evidence → AI (opsional) → Risk Engine → Risk Register → Excel
```

Spesifikasi lengkap ada di [docs/blueprint.md](docs/blueprint.md). Bagian "Catatan Pengembangan" di awal dokumen berisi keputusan yang berlaku saat ini.

## Fitur

- Input satu atau banyak website, satu per baris. Boleh tanpa `https://`, contoh `e-sakip.jemberkab.go.id`.
- Dua mode:
  - **Cepat** (maksimal 10 menit per website): DNS, HTTP, security headers, cookie, TLS dasar, teknologi, exposure terbatas, Nuclei profil ringan.
  - **Standar**: semua pemeriksaan Cepat, ditambah exposure lengkap, Nmap, Nuclei termasuk CVE, testssl.sh, WhatWeb, dan OWASP ZAP passive scan.
- Antrean: website diperiksa satu per satu. Di Mode Standar, Nuclei (dibatasi 15 request per detik, `NUCLEI_RATE_LIMIT`) berjalan di latar belakang sementara Nmap, testssl.sh, WhatWeb, dan ZAP dikerjakan, sehingga lama satu website hampir sama dengan lama Nuclei saja (uji e-sakip: 7,6 menit pada 15 request per detik; sebelumnya 11,5 menit pada 10 dan 23 menit pada 5, dengan hasil yang identik). Setiap website punya loading bar dengan persentase dan nama tahap yang sedang berjalan, diperbarui otomatis tanpa reload.
- Website yang kewalahan atau membatasi request: request Nuclei yang gagal (timeout, koneksi ditolak atau diputus) dicatat lewat `-elog`. Hanya request HTTP ke website itu sendiri (skema, host, dan port yang sama) yang dihitung, karena probe tcp/ssl/dns dan port lain yang tertutup memang wajar gagal (uji e-sakip: 61 dari 62 kegagalan termasuk jenis ini). Setelah Nuclei selesai, halaman utama juga dibuka lagi untuk mendeteksi 429, 5xx, atau halaman blokir WAF. Template yang gagal diulang pada 10 request per detik (`NUCLEI_RETRY_RATE_LIMIT`). Jika website memblokir (429, 5xx, atau halaman blokir WAF), seluruh run diulang setelah jeda 30 detik pada 5 request per detik (`NUCLEI_BLOCKED_RATE_LIMIT`), kecuali website masih memblokir setelah jeda. Jika setelah diulang masih banyak yang gagal, Nuclei dicatat ERROR dan website PARTIAL, jadi hasil yang tidak lengkap tidak dianggap lengkap. Pengulangan dicatat di ringkasan Nuclei.
- Halaman antrean dan halaman website menampilkan tanggal dan jam mulai, lama berjalan (diperbarui tiap detik), perkiraan sisa waktu, lalu jam selesai dan durasi. Lama Mode Standar (sekitar 8 menit) ditentukan Nuclei yang dibatasi 15 request per detik untuk sekitar 7.000 request (blueprint bagian 26).
- Hasil per website ditampilkan dalam lima tab: Overview, Security Check, Findings, Risk Register, dan Coverage. Hasil informasi Nuclei (severity info di luar katalog) dikelompokkan terpisah di tab Findings karena tidak masuk Risk Register. Tombol **Pindai Ulang** memeriksa ulang satu website atau satu batch dengan mode yang sama sebagai batch baru; hasil lama tetap tersimpan.
- Halaman **Riwayat** menampilkan semua batch (25 per halaman). Centang beberapa batch, semua batch di halaman itu, atau "Pilih semua riwayat", lalu **Hapus yang dipilih**: batch dihapus permanen beserta website, temuan, bukti, dan Risk Register-nya setelah konfirmasi. Batch yang masih berjalan tidak dapat dipilih. Hasil AI yang tersimpan per jenis temuan tidak ikut terhapus karena tidak memuat detail website.
- Coverage menampilkan status setiap kunci katalog (PASS, FAIL, N/A, ERROR, NOT ASSESSED) beserta pemeriksanya. Kunci yang tidak diperiksa pada suatu mode, karena tool tidak tersedia, dibatasi WAF, atau redirect tidak diikuti, dicatat NOT ASSESSED, bukan PASS.
- Hasil template Nuclei heuristik yang sering keliru (`waf-detect`, `s3-detect`, config `nuclei_raw_only`) hanya dicatat di daftar hasil Nuclei dan laporan mentah, bukan sebagai temuan; CDN/WAF memakai deteksi bawaan. Ringkasan CSP menampilkan isi header dan memberi catatan jika CSP tidak membatasi sumber script.
- Redirect hanya diikuti ke host yang sama atau yang hanya berbeda awalan `www.`. Tujuan redirect lain dicatat di evidence supaya dapat diperiksa sebagai target terpisah.
- Untuk kunci header (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy), pemeriksaan bawaan yang menentukan. Template Nuclei dan aturan ZAP hanya melihat header, sedangkan kriteria SIPRIKA juga menghitung tag meta dan direktif CSP `frame-ancestors`, sehingga temuan tool yang bertentangan dengan hasil PASS bawaan diabaikan.
- Risk Register tampil di web dengan tata letak sheet Perangkat Lunak pada template (judul, header, dan kolom A sampai AA), per website maupun gabungan satu batch. Isinya sama persis dengan file Excel hasil export.
- Risk Engine memakai katalog finding dan matriks risiko dari template (config, bukan kode). Residual Risk diisi sebagai perkiraan setelah Rencana Aksi dijalankan: dampak tetap, kemungkinan turun ke Hampir Tidak Terjadi (`config/siprika_risk.php`, kunci `residual`).
- AI lokal (qwen2.5 lewat llama.cpp) mengisi kolom deskriptif. Jika AI mati, SIPRIKA memakai teks katalog. Jawaban AI disimpan per kunci finding dan dipakai ulang, sehingga ditolak jika memuat CVE, versi, atau URL yang tidak ada di evidence website yang sedang diproses, atau memuat detail khusus satu website (host, nama file, nama cookie, versi).
- Supaya teks AI tidak mengarang, AI menerima teks katalog (dampak, rencana aksi, kontrol) sebagai acuan dan rekomendasi template scanner, diminta tidak melebih-lebihkan temuan kecil, dijawab dengan `temperature` 0, dan dibatasi schema JSON sehingga semua kolom selalu terisi. Hasil AI tersimpan ditandai versi prompt (`LlamaClient::PROMPT_VERSION`); jika prompt berubah, hasil lama tidak dipakai (kolom memakai teks katalog) dan dibuat ulang saat pemeriksaan berikutnya. Model 7B lokal kadang masih menghasilkan kalimat yang kurang luwes, jadi tinjau teks Risk Register sebelum diserahkan.
- Export Risk Register ke template Excel. Rumus, dropdown, dan sheet lain tetap utuh. Kolom Target/Jadwal, Penanggung Jawab, dan Risk Owner dikosongkan untuk diisi staf. Dua kesalahan template di sheet Ringkasan diperbaiki saat export: rumus persentase Acceptable yang membagi dengan jumlah Unacceptable, dan baris "SDM & Pihak Ketiga" yang mengambil total sheet Sarana Pendukung.
- **Laporan Mentah (Excel)**, terpisah dari template Risk Register (template tidak dibaca maupun diubah), per website atau per batch. Isinya 10 sheet: Ringkasan (waktu, IP, server, TLS, port, jumlah temuan), Tahap (jam mulai, selesai, dan lama setiap tahap), Pemeriksaan (semua pemeriksaan termasuk yang lolos), Temuan & Bukti, Teknologi, Port & Layanan, Nuclei, OWASP ZAP, testssl.sh, dan Coverage. Isi dari website target ditulis sebagai teks, bukan rumus. Sheet Nuclei dan OWASP ZAP berisi keluaran mentah tool dengan kolom "Dipakai sebagai" (menjadi temuan apa, informasi, atau alasan tidak dipakai), supaya hasil heuristik yang keliru tidak terbaca sebagai temuan.
- Perlindungan SSRF: localhost, alamat IP, dan domain yang mengarah ke IP privat ditolak.

## Kebutuhan

- PHP 8.3 dengan ekstensi curl, openssl, pdo_sqlite, intl, zip, dom (Laragon sudah cukup)
- Composer dan Node.js (untuk build CSS)
- Opsional, untuk Mode Standar dan Nuclei: WSL Ubuntu berisi `nuclei`, `testssl.sh`, `whatweb`, dan `nmap`
- Opsional, untuk AI: `llama-server` (llama.cpp build CPU Windows) dan model `qwen2.5-7b-instruct.Q4_K_M.gguf`, lihat bagian Model AI
- Opsional, untuk passive scan Mode Standar: OWASP ZAP 2.17 dan Java 17 (ZAP dijalankan sebagai daemon)

## Instalasi

```
composer install
npm install && npm run build
php artisan siprika:install
```

`siprika:install` membuat `.env` (jika belum ada), APP_KEY, database SQLite, menjalankan migrasi, lalu menampilkan ringkasan konfigurasi.

## Menjalankan

```
php artisan siprika:serve
```

Buka http://127.0.0.1:8000. Perintah ini menjalankan web server, queue worker, llama-server (jika `AI_SERVER_COMMAND` diisi), dan ZAP (jika `ZAP_SERVER_COMMAND` diisi). Setelah mengubah `.env`, hentikan (Ctrl+C) lalu jalankan ulang perintah ini, karena queue worker memakai environment saat pertama dijalankan.

Web server memakai OPcache jika tersedia (PHP Laragon sudah menyertakannya), sehingga halaman terbuka dalam puluhan milidetik. Database SQLite memakai mode WAL, jadi halaman tetap responsif walaupun pemeriksaan sedang menulis hasil. Jika port 8000 sudah dipakai, misalnya SIPRIKA sudah berjalan di jendela lain, perintah berhenti tanpa menjalankan apa pun. Jika port itu dipakai aplikasi lain, gunakan `php artisan siprika:serve --port=8001`.

Jika SIPRIKA dihentikan saat sebuah website sedang diperiksa, website itu ditandai gagal ketika `siprika:serve` dijalankan lagi dan antrean berikutnya langsung dilanjutkan. Gunakan tombol **Pindai Ulang** untuk memeriksanya kembali.

Setelah mengubah aturan risiko di `config/siprika_risk.php` atau memperbarui aplikasi, hitung ulang Risk Register batch yang sudah ada tanpa memindai ulang website dan tanpa memanggil AI:

```
php artisan siprika:recalculate 3      # batch nomor 3
php artisan siprika:recalculate --all  # semua batch
```

Perintah ini juga menghapus hasil AI tersimpan yang tidak lolos validasi terhadap evidence website, serta bukti Nuclei yang tidak lagi lolos aturan terbaru. Contohnya, template `weak-cipher-suites` dulu mencatat cipher AES-CBC biasa di TLS 1.0/1.1 sebagai "Cipher TLS lemah". Sekarang hanya cipher kategori lemah (NULL, anon, EXPORT, RC4, RC2, DES/3DES, IDEA) yang menjadi temuan itu, karena TLS 1.0/1.1 sendiri sudah tercatat sebagai "Protokol TLS lama".

Setelah memperbarui template Nuclei (`nuclei -ut`), pastikan kunci katalog yang dicatat dinilai Nuclei di Coverage masih sesuai template yang terpasang:

```
php artisan siprika:check-nuclei
```

`siprika:install` juga menguji verifikasi sertifikat ke website dengan sertifikat valid (`SCAN_TLS_SELFTEST_HOST`). Jika gagal, isi `SCAN_CA_BUNDLE` dengan CA bundle terbaru, karena tanpa itu semua website terbaca bersertifikat tidak valid.

## Model AI

Model dan llama.cpp disimpan di dalam folder SIPRIKA, supaya ikut saat folder disalin atau di-zip:

```
storage/app/models/qwen2.5-7b-instruct.Q4_K_M.gguf   (4,4 GB)
storage/app/llama.cpp/llama-server.exe               (beserta DLL-nya)
```

Folder `storage/app` tidak ikut git, jadi file 4,4 GB ini tidak ikut ter-push ke GitHub (GitHub menolak file di atas 100 MB). Jika mengambil SIPRIKA dari GitHub, unduh sendiri file GGUF model tersebut dan llama.cpp build CPU Windows, taruh di dua folder di atas, lalu isi `AI_SERVER_COMMAND` seperti contoh di `.env.example`. Path relatif dihitung dari folder SIPRIKA, jadi tetap jalan walaupun folder dipindah ke drive lain.

Pengaturan `-t 8` (8 thread) sudah diuji paling cepat di Core i7-13700H dengan `llama-bench` (sekitar 6,6 token per detik). Hasil AI disimpan per jenis temuan, sehingga hanya temuan baru yang menunggu AI (sekitar 40 detik).

## Membagikan SIPRIKA (zip)

```
php artisan siprika:package            # membuat siprika-<tanggal>.zip di samping folder SIPRIKA
php artisan siprika:package --dry-run  # hanya menampilkan jumlah file dan ukuran
```

Zip berisi aplikasi siap pakai termasuk `vendor`, aset tampilan, model AI, dan llama.cpp (sekitar 4,5 GB). Yang **tidak** ikut: `.env` (APP_KEY dan kunci ZAP), `database/database.sqlite` (hasil pemeriksaan website, data sensitif), log, dan cache.

Di laptop penerima:

1. Pasang Laragon (PHP 8.3). Untuk Mode Standar, pasang juga WSL Ubuntu berisi `nuclei`, `testssl.sh`, `whatweb`, `nmap`, serta OWASP ZAP dan Java 17 (opsional).
2. Ekstrak zip, buka terminal di folder `siprika`, jalankan `php artisan siprika:install`.
3. Sesuaikan `.env` (path tool, `AI_ENABLED=true`, `AI_SERVER_COMMAND`, `ZAP_*`), lalu jalankan `php artisan siprika:serve`.

## Konfigurasi (.env)

| Variabel | Keterangan |
|---|---|
| `SCAN_ALLOWED_DOMAINS` | `*` atau kosong berarti semua domain boleh diperiksa. Isi daftar dipisah koma untuk membatasi, contoh `jemberkab.go.id`. |
| `SCAN_TARGET_TIMEOUT`, `SCAN_QUICK_TARGET_TIMEOUT` | Batas waktu per website (detik) untuk Mode Standar (2700) dan Mode Cepat (600). |
| `SCAN_USER_AGENT` | User-Agent tetap supaya admin website mengenali pemeriksaan. |
| `NUCLEI_PATH`, `TESTSSL_PATH`, `WHATWEB_PATH`, `NMAP_PATH` | Perintah tool, contoh `"wsl -d Ubuntu -e nuclei"`. Kosong berarti pemeriksaan dicatat NOT ASSESSED. |
| `AI_ENABLED`, `AI_URL`, `AI_TIMEOUT` | AI lokal (llama-server, default port 8081). |
| `AI_SERVER_COMMAND` | Perintah llama-server yang ikut dijalankan `siprika:serve`. |
| `ZAP_URL`, `ZAP_API_KEY`, `ZAP_TIMEOUT` | API OWASP ZAP daemon untuk passive scan Mode Standar. Kosong berarti NOT ASSESSED. `ZAP_API_KEY` harus sama dengan `api.key` di perintah ZAP. |
| `ZAP_SERVER_COMMAND` | Perintah ZAP daemon yang ikut dijalankan `siprika:serve`, contoh di `.env.example`. |
| `SCAN_CA_BUNDLE`, `SCAN_TLS_SELFTEST_HOST` | CA bundle (kosong = trust store sistem) dan website uji verifikasi sertifikat. |

Katalog finding, aturan risiko, pola deteksi, dan profil Nuclei ada di `config/siprika*.php`. Semuanya bisa diubah tanpa mengubah kode.

## Struktur Kode

```
app/
├── Http/                  Halaman web: input dan antrean (ScanController), hasil per website (ScanTargetController)
├── Jobs/                  ProcessScanTarget: satu job antrean memeriksa satu website
├── Scanner/
│   ├── ScanOrchestrator   Menjalankan pemeriksaan sesuai mode secara berurutan
│   ├── ScanContext        Data bersama selama satu website diperiksa
│   ├── Checks/            Satu class per pemeriksaan (DNS, HTTP, header, cookie, TLS, exposure, tool eksternal)
│   ├── Parsers/           Mengubah output tool (Nuclei, testssl.sh, WhatWeb, Nmap, ZAP) menjadi finding
│   ├── Network/           HTTP client aman (SSRF), DNS, TLS, dan port
│   ├── Tools/             Menjalankan tool eksternal dari perintah di .env, dan klien API OWASP ZAP
│   ├── ScanQueue          Membuat batch dan antrean (input baru dan Pindai Ulang)
│   ├── CatalogCoverage    Status setiap kunci katalog untuk tab Coverage
│   └── FindingRecorder    Menyimpan finding dengan deduplikasi per kunci
├── Risk/                  RiskEngine (penilaian risiko) dan RiskRegisterExporter (Excel)
├── Ai/                    Klien llama-server, validasi output AI, dan analisis per finding
├── Enums/                 ScanMode (daftar pemeriksaan per mode), status, severity
├── Models/                Batch, target, observation, finding, evidence, Risk Register, hasil AI
└── Support/               TargetUrlNormalizer: normalisasi dan validasi URL input
config/siprika*.php        Pengaturan, katalog finding, aturan risiko, pola scanner
resources/templates/       Template Excel Risk Register
scripts/check-excel.ps1    Memeriksa file export di Microsoft Excel
resources/views/           Halaman Blade; tab hasil ada di views/targets/tabs
tests/                     Feature test, FakeNetwork (tanpa internet), fixture output tool asli
```

Alur satu website: `ProcessScanTarget` → `ScanOrchestrator` menjalankan setiap `Check` yang mencatat observation dan finding ke `ScanContext` → `FindingRecorder` → `AiAnalyzer` → `RiskEngine`.

Menambah pemeriksaan baru:

1. Buat class di `app/Scanner/Checks` yang mengimplementasikan `Check`.
2. Daftarkan di `ScanMode::STANDARD_CHECKS` (dan `QUICK_CHECKS` jika ikut Mode Cepat).
3. Jika menghasilkan finding baru, tambahkan kuncinya ke `config/siprika_catalog.php`.

## Test

```
php artisan test
vendor/bin/pint
```

Test tidak butuh internet atau tool eksternal. Akses jaringan diganti `tests/Support/FakeNetwork.php`, dan `phpunit.xml` mengosongkan path tool.

Setiap perubahan kode export diuji juga dengan membuka file hasilnya di Microsoft Excel (bagian 28 blueprint):

```
powershell -ExecutionPolicy Bypass -File scripts\check-excel.ps1 -Path "Risk Register SIPRIKA - Batch 3.xlsx" -ExpectedRows 6
```

Script membuka file lewat COM Excel lalu memeriksa: file terbuka tanpa perbaikan, rumus terhitung tanpa error, dropdown ada, dan sheet Ringkasan sesuai total sheet Perangkat Lunak. Exit code 1 jika ada yang gagal.

## Keamanan SIPRIKA

SIPRIKA dipakai satu orang di komputer sendiri tanpa login, jadi perlindungannya ditujukan terhadap website lain yang dibuka di browser yang sama:

- Web server hanya mendengarkan `127.0.0.1`. Permintaan dengan nama host selain alamat IP, `localhost`, atau host di `APP_URL` ditolak (status 400), supaya website penyerang tidak dapat membaca hasil pemeriksaan atau memulai pemeriksaan lewat DNS rebinding.
- Form memakai token CSRF, halaman tidak dapat dibingkai website lain (`X-Frame-Options: DENY`), dan semua isi dari website target ditampilkan dengan escape. Di Excel, isi dari website target ditulis sebagai teks, bukan rumus.
- Target diperiksa terhadap IP privat sebelum setiap permintaan dan sebelum tool eksternal dijalankan (perlindungan SSRF). Cookie dan isi file sensitif yang ditemukan disamarkan di evidence.
- Jangan menjalankan `siprika:serve --host=0.0.0.0` di jaringan yang tidak tepercaya: siapa pun di jaringan itu dapat melihat hasil dan memulai pemeriksaan.
- `database/database.sqlite` berisi daftar kerawanan website yang diperiksa. Jangan dibagikan (tidak ikut `siprika:package`).

## Batasan

SIPRIKA tidak melakukan eksploitasi, brute force, atau pemeriksaan yang membutuhkan login. Tidak ditemukannya kerawanan tidak berarti website sepenuhnya aman. Hanya periksa website yang Anda kelola atau yang sudah memberi izin.
