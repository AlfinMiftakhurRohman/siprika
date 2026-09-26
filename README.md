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
  - **Standar**: semua pemeriksaan Cepat, ditambah exposure lengkap, Nmap, Nuclei termasuk CVE, testssl.sh, dan WhatWeb.
- Antrean: website diperiksa satu per satu. Setiap website punya loading bar dengan persentase dan nama tahap yang sedang berjalan, diperbarui otomatis tanpa reload.
- Hasil per website ditampilkan dalam lima tab: Overview, Security Check, Findings, Risk Register, dan Coverage.
- Risk Register tampil di web dengan tata letak sheet Perangkat Lunak pada template (judul, header, dan kolom A sampai AA), per website maupun gabungan satu batch. Isinya sama persis dengan file Excel hasil export.
- Risk Engine memakai katalog finding dan matriks risiko dari template (config, bukan kode).
- AI lokal (qwen2.5 lewat llama.cpp) mengisi kolom deskriptif. Jika AI mati, SIPRIKA memakai teks katalog.
- Export Risk Register ke template Excel. Rumus, dropdown, dan sheet lain tetap utuh.
- Perlindungan SSRF: localhost, alamat IP, dan domain yang mengarah ke IP privat ditolak.

## Kebutuhan

- PHP 8.3 dengan ekstensi curl, openssl, pdo_sqlite, intl, zip, dom (Laragon sudah cukup)
- Composer dan Node.js (untuk build CSS)
- Opsional, untuk Mode Standar dan Nuclei: WSL Ubuntu berisi `nuclei`, `testssl.sh`, `whatweb`, dan `nmap`
- Opsional, untuk AI: `llama-server` (llama.cpp) dan model `qwen2.5-7b-instruct.Q4_K_M.gguf`

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

Buka http://127.0.0.1:8000. Perintah ini menjalankan web server, queue worker, dan llama-server (jika `AI_SERVER_COMMAND` diisi). Setelah mengubah `.env`, hentikan (Ctrl+C) lalu jalankan ulang perintah ini, karena queue worker memakai environment saat pertama dijalankan.

## Konfigurasi (.env)

| Variabel | Keterangan |
|---|---|
| `SCAN_ALLOWED_DOMAINS` | `*` atau kosong berarti semua domain boleh diperiksa. Isi daftar dipisah koma untuk membatasi, contoh `jemberkab.go.id`. |
| `SCAN_TARGET_TIMEOUT`, `SCAN_QUICK_TARGET_TIMEOUT` | Batas waktu per website (detik) untuk Mode Standar (2700) dan Mode Cepat (600). |
| `SCAN_USER_AGENT` | User-Agent tetap supaya admin website mengenali pemeriksaan. |
| `NUCLEI_PATH`, `TESTSSL_PATH`, `WHATWEB_PATH`, `NMAP_PATH` | Perintah tool, contoh `"wsl -d Ubuntu -e nuclei"`. Kosong berarti pemeriksaan dicatat NOT ASSESSED. |
| `AI_ENABLED`, `AI_URL`, `AI_TIMEOUT` | AI lokal (llama-server, default port 8081). |
| `AI_SERVER_COMMAND` | Perintah llama-server yang ikut dijalankan `siprika:serve`. |

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
│   ├── Parsers/           Mengubah output tool (Nuclei, testssl.sh, WhatWeb, Nmap) menjadi finding
│   ├── Network/           HTTP client aman (SSRF), DNS, TLS, dan port
│   ├── Tools/             Menjalankan tool eksternal dari perintah di .env
│   └── FindingRecorder    Menyimpan finding dengan deduplikasi per kunci
├── Risk/                  RiskEngine (penilaian risiko) dan RiskRegisterExporter (Excel)
├── Ai/                    Klien llama-server, validasi output AI, dan analisis per finding
├── Enums/                 ScanMode (daftar pemeriksaan per mode), status, severity
├── Models/                Batch, target, observation, finding, evidence, Risk Register, hasil AI
└── Support/               TargetUrlNormalizer: normalisasi dan validasi URL input
config/siprika*.php        Pengaturan, katalog finding, aturan risiko, pola scanner
resources/templates/       Template Excel Risk Register
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

## Batasan

SIPRIKA tidak melakukan eksploitasi, brute force, atau pemeriksaan yang membutuhkan login. Tidak ditemukannya kerawanan tidak berarti website sepenuhnya aman. Hanya periksa website yang Anda kelola atau yang sudah memberi izin.
