# Panduan SIPRIKA

Panduan ini ditujukan untuk siapa saja yang menerima SIPRIKA dalam bentuk zip dan ingin memakainya di laptop Windows sendiri. Isinya mencakup apa yang perlu dipasang, cara menyiapkan, cara memakai, dan cara mengatasi masalah yang sering muncul. Catatan teknis untuk pengembang ada di [README.md](README.md), sedangkan spesifikasi lengkapnya di [docs/blueprint.md](docs/blueprint.md).

## Daftar Isi

1. [Apa itu SIPRIKA](#1-apa-itu-siprika)
2. [Kebutuhan laptop](#2-kebutuhan-laptop)
3. [Isi zip](#3-isi-zip)
4. [Instalasi dasar (wajib)](#4-instalasi-dasar-wajib)
5. [Mengaktifkan AI (opsional)](#5-mengaktifkan-ai-opsional)
6. [Memasang tool di WSL (disarankan)](#6-memasang-tool-di-wsl-disarankan)
7. [Memasang OWASP ZAP (opsional)](#7-memasang-owasp-zap-opsional)
8. [Pengaturan lain di .env](#8-pengaturan-lain-di-env)
9. [Cara memakai SIPRIKA](#9-cara-memakai-siprika)
10. [Membaca hasil](#10-membaca-hasil)
11. [Masalah yang sering muncul](#11-masalah-yang-sering-muncul)
12. [Keamanan dan etika](#12-keamanan-dan-etika)
13. [Membagikan, memperbarui, dan memindahkan SIPRIKA](#13-membagikan-memperbarui-dan-memindahkan-siprika)
14. [Referensi cepat](#14-referensi-cepat)

---

## 1. Apa itu SIPRIKA

SIPRIKA (Sistem Penilaian Risiko Keamanan Aplikasi) memeriksa keamanan dasar website secara otomatis dan **non-eksploitatif**: tanpa eksploitasi, tanpa menebak password, dan tanpa login. Hasil pemeriksaan disusun menjadi Risk Register sesuai template Excel kantor (sheet Perangkat Lunak).

```
Daftar website → Pemeriksaan → Temuan + bukti → Penilaian risiko → Risk Register (Excel)
```

Yang diperiksa SIPRIKA:

- DNS dan alamat IP
- HTTP dan redirect
- Security headers dan cookie
- Sertifikat dan versi TLS
- Teknologi yang dipakai website
- File sensitif yang terbuka ke publik
- Port layanan web
- Hasil tool keamanan: Nuclei, testssl.sh, WhatWeb, Nmap, dan OWASP ZAP (passive scan)

Hasil yang didapat:

- Tampilan hasil per website di browser.
- **Risk Register (Excel)** sesuai template kantor, siap dilengkapi.
- **Laporan Mentah (Excel)** berisi semua pemeriksaan dan bukti untuk dicek ulang.

SIPRIKA berjalan di laptop sendiri (alamat http://127.0.0.1:8000), tanpa server dan tanpa akun. **Hanya periksa website yang Anda kelola atau yang sudah memberi izin.**

---

## 2. Kebutuhan laptop

| | Minimal | Disarankan |
|---|---|---|
| Sistem operasi | Windows 10 versi 2004 (build 19041) 64-bit | Windows 11 64-bit |
| RAM | 8 GB (tanpa AI) | 16 GB (dengan AI) |
| Ruang disk kosong | 12 GB | 20 GB |
| Prosesor | 4 core | 8 core atau lebih (AI lebih cepat) |
| Internet | Stabil | Kabel LAN, terutama untuk banyak website |
| Virtualisasi | Aktif (untuk WSL) | |

Cara mengecek virtualisasi: buka Task Manager → **Performance** → **CPU**, lalu lihat tulisan **Virtualization: Enabled**. Jika tertulis Disabled, aktifkan Intel VT-x atau AMD-V di BIOS/UEFI.

Komponen yang perlu dipasang:

| Komponen | Wajib? | Fungsinya | Jika tidak dipasang |
|---|---|---|---|
| PHP 8.3 | **Wajib** | Menjalankan SIPRIKA | SIPRIKA tidak bisa jalan |
| AI lokal (sudah ada di zip) | Opsional | Mengisi kolom deskriptif Risk Register | Kolom diisi teks katalog bawaan |
| WSL Ubuntu + Nuclei, testssl.sh, WhatWeb, Nmap | Disarankan | Pemeriksaan tool di Mode Cepat dan Mode Standar | Pemeriksaan itu dicatat NOT ASSESSED |
| Java 17 + OWASP ZAP 2.17 | Opsional | Passive scan di Mode Standar | ZAP dicatat NOT ASSESSED |
| Microsoft Excel | Disarankan | Membuka hasil export | |

Yang **tidak** perlu dipasang: Composer, Node.js, MySQL, Apache, atau XAMPP. Semua kebutuhan PHP sudah ada di dalam zip.

---

## 3. Isi zip

Setelah diekstrak, folder `siprika` berisi:

| File/folder | Isi |
|---|---|
| `jalankan-siprika.bat` | Klik dua kali untuk menjalankan SIPRIKA |
| `PANDUAN.md` | Panduan ini |
| `README.md` | Catatan teknis untuk pengembang |
| `.env.example` | Contoh pengaturan. Salinannya, `.env`, dibuat otomatis saat SIPRIKA pertama kali dijalankan |
| `storage/app/models/` | Model AI qwen2.5 7B (4,4 GB) |
| `storage/app/llama.cpp/` | Program AI lokal (llama-server) |
| `resources/templates/` | Template Excel Risk Register |
| `docs/blueprint.md` | Spesifikasi lengkap SIPRIKA |

Ada dua file yang sengaja **tidak** ikut:

- `.env` milik pengirim, karena berisi kunci rahasia.
- `database/database.sqlite`, karena berisi riwayat pemeriksaan website (data sensitif).

Laptop Anda akan membuat keduanya sendiri saat SIPRIKA pertama kali dijalankan.

---

## 4. Instalasi dasar (wajib)

Bagian ini sudah cukup untuk menjalankan SIPRIKA dengan pemeriksaan bawaan. Tool tambahan dan AI dipasang di bagian 5 sampai 7.

### 4.1 Ekstrak zip

1. Klik kanan file zip → **Properties**, centang **Unblock** jika ada, lalu klik **OK**. Langkah ini mencegah peringatan Windows SmartScreen saat file dijalankan.
2. Ekstrak ke folder dengan path pendek, contoh `C:\SIPRIKA`. Caranya: klik kanan → **Extract All**, ganti tujuannya menjadi `C:\SIPRIKA`, atau pakai 7-Zip. Hasilnya adalah folder `C:\SIPRIKA\siprika`.
3. Jangan menjalankan SIPRIKA langsung dari dalam zip, dan jangan menaruhnya di folder yang disinkronkan OneDrive.

### 4.2 Memasang PHP

Lewati langkah ini jika perintah `php -v` di Command Prompt sudah menampilkan PHP 8.3. Versi yang sudah diuji untuk SIPRIKA adalah PHP 8.3.

**Cara A: PHP resmi (tanpa Laragon)**

1. Pasang **Microsoft Visual C++ Redistributable x64** dari https://aka.ms/vs/17/release/vc_redist.x64.exe. Program AI juga membutuhkannya.
2. Unduh PHP 8.3 versi **VS16 x64 Thread Safe** (file zip) dari https://windows.php.net/download/, lalu ekstrak ke `C:\php` sehingga ada file `C:\php\php.exe`.
3. Di folder `C:\php`, salin file `php.ini-development` lalu ganti nama salinannya menjadi `php.ini`. Buka `php.ini` dengan Notepad, lalu:
   - Cari baris `;extension_dir = "ext"` (baris untuk Windows) dan ganti menjadi `extension_dir = "C:\php\ext"`.
   - Hapus tanda `;` di awal tujuh baris berikut:
     ```
     extension=curl
     extension=fileinfo
     extension=gd
     extension=mbstring
     extension=openssl
     extension=pdo_sqlite
     extension=zip
     ```
   - Simpan file.
4. Tambahkan `C:\php` ke PATH:
   - Tekan Start, ketik **environment**, lalu pilih **Edit environment variables for your account**.
   - Pilih **Path** → **Edit** → **New**, isi `C:\php`.
   - Klik **OK** di semua jendela.

**Cara B: Laragon (jika sudah terpasang)**

1. Pilih PHP 8.3 lewat menu Laragon → **PHP** → **Version**. Jika belum ada, unduh zip PHP 8.3 dari https://windows.php.net/download/ lalu ekstrak ke `C:\laragon\bin\php\`.
2. Masukkan PHP ke PATH lewat menu Laragon → **Tools** → **Path** → **Add Laragon to Path**.
3. Jika nanti ada ekstensi yang kurang, aktifkan lewat menu Laragon → **PHP** → **Extensions**.

**Mengecek PHP**

Buka Command Prompt **baru**, lalu jalankan:

```
php -v
php -m
```

Hasil yang benar:

- `php -v` menampilkan `PHP 8.3`.
- Daftar dari `php -m` memuat `curl`, `fileinfo`, `gd`, `mbstring`, `openssl`, `pdo_sqlite`, dan `zip`.

Jika ada ekstensi yang belum aktif, SIPRIKA akan menyebutkannya saat pertama kali dijalankan.

### 4.3 Menjalankan pertama kali

1. Buka folder `C:\SIPRIKA\siprika`, lalu klik dua kali **`jalankan-siprika.bat`**. Jika muncul peringatan **Windows protected your PC**, klik **More info** → **Run anyway**.
2. Saat pertama kali, SIPRIKA menyiapkan diri: membuat `.env`, kunci aplikasi (APP_KEY), dan database, lalu menampilkan ringkasan pengaturan. Pastikan baris **Uji verifikasi sertifikat TLS** menunjukkan **berhasil**. Jika gagal, lihat bagian 11.
3. Sekitar 8 detik kemudian, browser terbuka otomatis ke **http://127.0.0.1:8000**. Jika tidak terbuka, buka alamat itu sendiri.
4. **Jendela hitam SIPRIKA harus tetap terbuka** selama SIPRIKA dipakai. Menutupnya akan menghentikan SIPRIKA beserta pemeriksaan yang sedang berjalan.

Sampai tahap ini SIPRIKA sudah bisa dipakai dengan pemeriksaan bawaan (DNS, HTTP, header, cookie, TLS, teknologi, dan file sensitif). Selama bagian 5 sampai 7 belum dikerjakan, pemeriksaan tool dicatat NOT ASSESSED dan Risk Register memakai teks katalog.

### 4.4 Cara mengubah pengaturan

Semua pengaturan ada di file `.env` di folder `siprika`. Buka file itu dengan Notepad (klik kanan → **Open with** → **Notepad**). Aturannya:

- Baris yang diawali `#` hanyalah contoh. Hapus `#` untuk memakainya.
- **Setiap kali `.env` diubah, tutup jendela SIPRIKA lalu jalankan lagi `jalankan-siprika.bat`.**

Beberapa langkah memakai Command Prompt di folder SIPRIKA. Cara membukanya: buka folder `siprika` di File Explorer, klik address bar, ketik `cmd`, lalu tekan Enter.

Untuk melihat ringkasan pengaturan yang sedang berlaku, jalankan perintah berikut. Perintah ini aman diulang dan tidak menghapus data.

```
php artisan siprika:install
```

---

## 5. Mengaktifkan AI (opsional)

AI lokal (model qwen2.5 7B lewat llama.cpp) menulis kolom deskriptif Risk Register, seperti dampak, rencana aksi, dan kontrol, berdasarkan temuan. File model dan programnya sudah ada di zip, jadi tinggal diaktifkan. Tanpa AI, kolom tersebut diisi teks katalog yang sudah disiapkan dan Risk Register tetap valid.

AI membutuhkan RAM sekitar 6 GB, sehingga disarankan laptop dengan RAM 16 GB.

1. Di `.env`, ganti kedua baris berikut. Baris `AI_SERVER_COMMAND=` yang masih kosong diganti dengan baris lengkap:
   ```
   AI_ENABLED=true
   AI_SERVER_COMMAND="storage/app/llama.cpp/llama-server.exe -m storage/app/models/qwen2.5-7b-instruct.Q4_K_M.gguf --host 127.0.0.1 --port 8081 -c 8192 -t 8 --no-webui"
   ```
2. Ganti `-t 8` dengan jumlah core prosesor laptop (lihat Task Manager → **Performance** → **CPU** → **Cores**). Contoh untuk laptop 4 core: `-t 4`.
3. Jalankan ulang SIPRIKA. Program AI ikut berjalan otomatis di port 8081 dan siap dalam sekitar 10 sampai 20 detik.

Hal yang perlu diketahui tentang AI:

- AI butuh sekitar 40 sampai 60 detik untuk setiap jenis temuan baru. Hasilnya disimpan dan dipakai ulang untuk website lain dengan temuan yang sama, jadi pemeriksaan berikutnya lebih cepat.
- Batas waktu satu permintaan AI adalah 60 detik. Jika terlewati, kolom diisi teks katalog.
- Model 7B kadang menghasilkan kalimat yang kurang luwes, jadi **tinjau teks Risk Register sebelum diserahkan**.

---

## 6. Memasang tool di WSL (disarankan)

Nuclei, testssl.sh, WhatWeb, dan Nmap berjalan di Linux (Ubuntu) di dalam Windows lewat WSL. Nuclei dipakai di Mode Cepat maupun Mode Standar.

### 6.1 Memasang WSL dan Ubuntu

1. Buka **PowerShell sebagai Administrator** (Start → ketik `powershell` → klik kanan → **Run as administrator**), lalu jalankan:
   ```
   wsl --install -d Ubuntu
   ```
2. Restart laptop jika diminta. Setelah jendela Ubuntu terbuka, buat **username** dan **password** Linux. Password memang tidak terlihat saat diketik. Simpan password ini karena dipakai untuk perintah `sudo`.
3. Di Command Prompt, cek nama distro:
   ```
   wsl -l -v
   ```
   Hasilnya harus memuat `Ubuntu` dengan VERSION `2`. Jika namanya berbeda (contoh `Ubuntu-24.04`), pakai nama itu sebagai pengganti `Ubuntu` di semua perintah dan di `.env`.

### 6.2 Memasang tool di Ubuntu

Buka **Ubuntu** dari Start menu, lalu jalankan perintah di bawah blok per blok. Untuk menempel di jendela Ubuntu, klik kanan.

Paket dasar dan Nmap:

```bash
sudo apt update
sudo apt install -y nmap git curl unzip ruby ruby-addressable bsdextrautils bind9-dnsutils
```

Nuclei beserta template pemeriksaannya. Perintah `nuclei -ut` mengunduh template sekitar 85 MB.

```bash
cd /tmp
curl -LO https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_linux_amd64.zip
unzip -o nuclei_3.11.1_linux_amd64.zip nuclei
sudo install -m 755 nuclei /usr/local/bin/nuclei
nuclei -ut
```

testssl.sh:

```bash
git clone --depth 1 https://github.com/testssl/testssl.sh.git ~/tools/testssl.sh
sudo ln -sf ~/tools/testssl.sh/testssl.sh /usr/local/bin/testssl.sh
```

WhatWeb dipasang dari git karena paket `whatweb` dari apt di Ubuntu terbaru rusak (`cannot load such file -- /usr/bin/lib/messages`):

```bash
git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git ~/tools/WhatWeb
sudo ln -sf ~/tools/WhatWeb/whatweb /usr/local/bin/whatweb
```

Semua tool harus berada di `/usr/local/bin` atau `/usr/bin`. SIPRIKA memanggil tool tanpa membuka shell Ubuntu, jadi pengaturan PATH di `.bashrc` tidak terbaca.

### 6.3 Mengecek dari Windows

Jalankan perintah berikut di Command Prompt Windows. Setiap perintah harus menampilkan versi tool:

```
wsl -d Ubuntu -e nuclei -version
wsl -d Ubuntu -e testssl.sh --version
wsl -d Ubuntu -e whatweb --version
wsl -d Ubuntu -e nmap --version
```

Jika WhatWeb menampilkan error gem yang hilang, misalnya `cannot load such file -- getoptlong`, pasang gem itu di Ubuntu dengan `sudo gem install getoptlong`.

### 6.4 Mengisi .env

Isi baris berikut di `.env`:

```
NUCLEI_PATH="wsl -d Ubuntu -e nuclei"
TESTSSL_PATH="wsl -d Ubuntu -e testssl.sh"
WHATWEB_PATH="wsl -d Ubuntu -e whatweb"
NMAP_PATH="wsl -d Ubuntu -e nmap"
```

Setelah itu jalankan ulang SIPRIKA, lalu pastikan template Nuclei cocok dengan SIPRIKA:

```
php artisan siprika:check-nuclei
```

---

## 7. Memasang OWASP ZAP (opsional)

ZAP menjalankan passive scan di Mode Standar. Passive scan hanya membaca respons website, tanpa mengirim serangan.

1. Pasang **Java 17**: unduh Eclipse Temurin 17 untuk Windows x64 (file `.msi`) dari https://adoptium.net/temurin/releases/?version=17. Saat instalasi, pastikan **Add to PATH** aktif. Cek di Command Prompt baru dengan `java -version`; hasilnya harus `17.x`.
2. Pasang **ZAP 2.17**: unduh **Windows (64) Installer** dari https://www.zaproxy.org/download/ dan pasang di lokasi bawaan. Pastikan file `C:\Program Files\ZAP\Zed Attack Proxy\zap-2.17.0.jar` ada. Jika versi ZAP berbeda, sesuaikan nama file `.jar` di langkah 4.
3. Buat kunci API acak dengan menjalankan perintah ini di PowerShell, lalu salin hasilnya:
   ```
   [guid]::NewGuid().ToString("N")
   ```
4. Isi `.env`. Ganti `KUNCI_ANDA` dengan kunci dari langkah 3 di **dua tempat**:
   ```
   ZAP_URL=http://127.0.0.1:8080
   ZAP_API_KEY=KUNCI_ANDA
   ZAP_SERVER_COMMAND='java -Xmx512m -jar "C:/Program Files/ZAP/Zed Attack Proxy/zap-2.17.0.jar" -daemon -host 127.0.0.1 -port 8080 -config api.key=KUNCI_ANDA -config api.addrs.addr.name=127.0.0.1 -config api.addrs.addr.regex=false'
   ```
5. Jalankan ulang SIPRIKA. ZAP ikut berjalan otomatis. Saat pertama kali, ZAP bisa butuh sampai 30 detik untuk siap.

Jika port 8080 sudah dipakai aplikasi lain, ganti `8080` di `ZAP_URL` dan di `ZAP_SERVER_COMMAND` dengan port lain yang kosong, contoh 8090.

---

## 8. Pengaturan lain di .env

| Pengaturan | Bawaan | Keterangan |
|---|---|---|
| `SCAN_ALLOWED_DOMAINS` | `*` (semua domain) | **Sangat disarankan** diisi domain instansi, contoh `jemberkab.go.id`. Website di luar domain ini dan subdomainnya ditolak saat input. Beberapa domain dipisah koma. |
| `SCAN_USER_AGENT` | `SIPRIKA/1.0 (Diskominfo Jember)` | Identitas pemeriksaan yang tercatat di log website. Sesuaikan dengan nama instansi Anda. |
| `SCAN_TARGET_TIMEOUT` / `SCAN_QUICK_TARGET_TIMEOUT` | 2700 / 600 | Batas waktu per website dalam detik, untuk Mode Standar / Mode Cepat. |
| `SCAN_OFFLINE_WAIT` | 1800 | Lama antrean menunggu internet kembali saat laptop offline (detik). |
| `NUCLEI_RATE_LIMIT` | 15 | Jumlah maksimal request Nuclei per detik per website. Baris ini diawali `#` di `.env`; hapus `#` untuk mengubahnya. |
| `SCAN_CA_BUNDLE` | kosong | Path CA bundle, dipakai jika uji sertifikat TLS gagal (lihat bagian 11). |
| `AI_TIMEOUT` | 60 | Batas waktu satu permintaan AI (detik). |

---

## 9. Cara memakai SIPRIKA

### 9.1 Memulai pemeriksaan

1. Jalankan `jalankan-siprika.bat`, lalu buka http://127.0.0.1:8000 (halaman **Pemeriksaan Baru**).
2. Di kolom **Target Website**, isi satu website per baris. Boleh tanpa `https://`, contoh:
   ```
   e-sakip.jemberkab.go.id
   https://website-b.jemberkab.go.id
   ```
3. Pilih **Mode Pemeriksaan**:

   | Mode | Isi pemeriksaan | Lama per website |
   |---|---|---|
   | **Cepat** | DNS, HTTP, security headers, cookie, TLS dasar, teknologi, file sensitif terbatas, dan Nuclei profil ringan | Sekitar 2 menit (maksimal 10) |
   | **Standar** | Semua isi Mode Cepat, ditambah file sensitif lengkap, Nmap, Nuclei termasuk CVE, testssl.sh, WhatWeb, dan OWASP ZAP passive | Sekitar 8 menit (maksimal 45) |

4. Klik **MULAI PEMERIKSAAN**. Website diperiksa satu per satu sesuai urutan.

Sebagai gambaran, 10 website di Mode Standar butuh sekitar 1,5 jam, dan 100 website sekitar 13 jam. Untuk memeriksa banyak website:

- Pakai kabel LAN.
- Pasang charger.
- Atur laptop supaya tidak tidur: Settings → System → Power → **Screen and sleep** → **Never** saat dicas.
- Jika laptop akan ditutup, atur Control Panel → Power Options → **Choose what closing the lid does** → **Do nothing** saat dicas.

### 9.2 Memantau antrean

Halaman **Antrean Pemeriksaan #N** menampilkan setiap website lengkap dengan progress bar, tahap yang sedang berjalan, jam mulai, lama berjalan, dan perkiraan sisa waktu. Halaman ini diperbarui otomatis.

- **Batalkan yang Menunggu** membatalkan website yang belum mulai diperiksa.
- Jika internet laptop putus, website berikutnya menampilkan **Menunggu koneksi internet**. Pemeriksaan lanjut sendiri setelah koneksi kembali. Website yang sedang diperiksa saat koneksi putus akan diperiksa ulang otomatis di akhir antrean.
- Halaman browser boleh ditutup. Pemeriksaan tetap berjalan selama jendela SIPRIKA terbuka, dan bisa dibuka lagi lewat menu **Riwayat**.

### 9.3 Melihat hasil

Klik **Lihat Hasil** pada sebuah website. Hasilnya dibagi ke lima tab:

| Tab | Isi |
|---|---|
| **Overview** | Ringkasan website (judul halaman, IP, web server, TLS, redirect, teknologi) dan jumlah temuan |
| **Security Check** | Semua pemeriksaan beserta statusnya |
| **Findings** | Temuan beserta bukti, seperti URL, header, dan nilai yang terbaca |
| **Risk Register** | Baris risiko seperti di sheet Perangkat Lunak |
| **Coverage** | Status setiap jenis pemeriksaan di katalog, termasuk yang tidak dinilai |

### 9.4 Mengunduh laporan

Tombol berikut tersedia di halaman antrean (untuk semua website) atau di halaman hasil (untuk satu website):

- **Lihat Risk Register**: menampilkan Risk Register gabungan satu batch di browser.
- **Export Risk Register (Excel)**: file Excel sesuai template kantor. Rumus, dropdown, dan sheet Ringkasan sudah terisi. Lengkapi kolom **Target/Jadwal**, **Penanggung Jawab**, dan **Risk Owner** secara manual, lalu tinjau teks deskriptifnya.
- **Laporan Mentah (Excel)**: 10 sheet berisi semua pemeriksaan, temuan dan bukti, teknologi, port, serta keluaran mentah tool. Laporan ini berguna untuk mengecek ulang dasar setiap temuan.

### 9.5 Memeriksa ulang

Kedua tombol berikut muncul setelah semua website di batch selesai diperiksa:

- **Pindai Ulang** memeriksa ulang semua website di batch sebagai batch baru (dari halaman hasil, hanya website itu). Hasil lama tetap tersimpan, sehingga cocok untuk membandingkan kondisi sebelum dan sesudah perbaikan.
- **Pindai Ulang yang Gagal (N)** hanya memeriksa ulang website berstatus Gagal atau Sebagian gagal, di batch yang sama. Hasil lama website tersebut diganti. Tombol ini cocok dipakai setelah ada gangguan koneksi, supaya satu batch tetap lengkap.

### 9.6 Riwayat

Menu **Riwayat** menampilkan semua batch. Untuk menghapus, centang batch yang diinginkan lalu klik **Hapus yang dipilih**. Batch akan terhapus permanen beserta hasil dan Risk Register-nya. Batch yang masih berjalan tidak bisa dihapus.

### 9.7 Menghentikan SIPRIKA

Tutup jendela SIPRIKA, atau tekan Ctrl+C di jendela itu. Yang terjadi saat SIPRIKA dijalankan lagi:

- Website yang masih menunggu akan dilanjutkan otomatis.
- Website yang sedang diperiksa saat SIPRIKA dihentikan akan ditandai Gagal. Setelah batch selesai, periksa ulang dengan **Pindai Ulang yang Gagal**.

---

## 10. Membaca hasil

### Status website

| Status | Arti |
|---|---|
| Menunggu | Belum diperiksa (termasuk saat menunggu koneksi internet) |
| Sedang diperiksa | Pemeriksaan sedang berjalan |
| Selesai | Semua pemeriksaan berhasil dijalankan |
| Sebagian gagal | Ada pemeriksaan yang ERROR, contoh karena timeout. Hasil lainnya tetap valid |
| Gagal | Website tidak dapat diperiksa sama sekali. Alasannya ditampilkan, contoh domain tidak ditemukan di DNS atau website tidak dapat diakses |
| Dibatalkan | Dibatalkan sebelum diperiksa |

### Status pemeriksaan

| Status | Arti |
|---|---|
| PASS | Sesuai kriteria keamanan |
| FAIL | Terbukti bermasalah, sehingga menjadi temuan |
| INFO | Informasi, bukan temuan (contoh teknologi yang terdeteksi) |
| ERROR | Gagal diperiksa karena timeout, koneksi terputus, atau tool error. **Bukan temuan, tetapi juga bukan berarti aman** |
| N/A | Tidak berlaku untuk website ini, contoh HSTS pada website yang tidak menyediakan HTTPS |
| NOT ASSESSED | Tidak dinilai karena tool belum dipasang, pemeriksaan hanya ada di Mode Standar, atau respons diblokir WAF/CDN. **Bukan berarti aman** |

### Tingkat risiko

Setiap temuan diberi nilai **dampak** (Tidak Signifikan sampai Sangat Signifikan) dan **kemungkinan** (Hampir Tidak Terjadi sampai Hampir Pasti Terjadi). Dari dua nilai itu, matriks risiko di template menghasilkan nilai **IR** (1 sampai 25) dan level **Sangat Rendah, Rendah, Sedang, Tinggi, atau Sangat Tinggi**.

- Risiko dengan IR 11 ke atas berstatus **Not Acceptable** dan perlu ditangani.
- Kolom Residual Risk adalah perkiraan setelah rencana aksi dijalankan.

Perlu diingat: tidak adanya temuan **tidak berarti website sepenuhnya aman**. SIPRIKA hanya memeriksa hal yang terlihat dari luar, tanpa login.

---

## 11. Masalah yang sering muncul

| Gejala | Penyebab | Solusi |
|---|---|---|
| "PHP tidak ditemukan" | PHP belum terpasang atau belum masuk PATH | Ikuti bagian 4.2. Setelah PATH diubah, buka jendela baru |
| "Ekstensi PHP belum aktif: ..." | Ekstensi belum diaktifkan di `php.ini` | Hapus `;` di depan baris `extension=...` yang disebut, simpan, lalu jalankan lagi |
| "Port 8000 sudah dipakai" | SIPRIKA sudah berjalan di jendela lain | Buka http://127.0.0.1:8000, atau tutup jendela lain itu. Jika port dipakai aplikasi lain, jalankan `php artisan siprika:serve --port=8001` |
| Browser: "This site can't be reached" | SIPRIKA belum siap atau jendelanya tertutup | Tunggu beberapa detik lalu refresh. Pastikan jendela SIPRIKA terbuka |
| "Nama host tidak dikenal" (error 400) | SIPRIKA dibuka lewat nama host lain | Buka lewat http://127.0.0.1:8000 atau http://localhost:8000 |
| Banyak website **Gagal: DNS gagal**, atau muncul **Menunggu koneksi internet** | Internet laptop putus, biasanya karena Wi-Fi lemah | Perbaiki koneksi (kabel LAN, atau lebih dekat ke router). Setelah batch selesai, klik **Pindai Ulang yang Gagal** |
| Pemeriksaan tool **NOT ASSESSED** dengan keterangan belum dipasang | Path tool di `.env` masih kosong | Ikuti bagian 6.4, lalu jalankan ulang SIPRIKA |
| Pemeriksaan tool **ERROR**, contoh "Tool gagal (exit code ...)" | Tool di WSL tidak bisa dijalankan | Jalankan perintah cek di bagian 6.3. Pastikan nama distro di `.env` sesuai |
| OWASP ZAP **ERROR** | Java tidak ada di PATH, port 8080 dipakai, atau kunci API berbeda | Cek `java -version`. Samakan kunci di `ZAP_API_KEY` dan `api.key=`. Ganti port jika perlu |
| "Layanan AI tidak dapat dihubungi atau timeout, dipakai teks katalog" | AI belum aktif, RAM kurang, atau laptop lambat | Ikuti bagian 5. Tutup aplikasi lain, atau matikan AI (`AI_ENABLED=false`) |
| Program AI tidak mau jalan (DLL tidak ditemukan) | Visual C++ Redistributable belum terpasang | Pasang `vc_redist.x64.exe` (bagian 4.2) |
| Uji sertifikat TLS **gagal** saat persiapan | CA bundle tidak terbaca | Unduh https://curl.se/ca/cacert.pem dan simpan, contoh di `C:\php\cacert.pem`. Isi `SCAN_CA_BUNDLE=C:/php/cacert.pem`, lalu jalankan ulang |
| Header, cookie, atau file sensitif **NOT ASSESSED** karena WAF/CDN | Website memblokir SIPRIKA, contoh lewat Cloudflare Bot Fight Mode | Minta admin website mengizinkan User-Agent SIPRIKA atau IP laptop selama pemeriksaan |
| `.env` sudah diubah tetapi tidak berpengaruh | SIPRIKA belum dijalankan ulang | Tutup jendela SIPRIKA, lalu jalankan lagi |
| "Allowed memory size ... exhausted" saat export | Batas memori PHP terlalu kecil | Naikkan `memory_limit` di `php.ini`, contoh menjadi `512M` |

Catatan kesalahan lengkap tersimpan di `storage/logs/laravel.log`.

---

## 12. Keamanan dan etika

- Hanya periksa website milik instansi Anda atau yang sudah memberi izin. Isi `SCAN_ALLOWED_DOMAINS` supaya domain lain tertolak.
- SIPRIKA tidak melakukan eksploitasi, brute force, atau login. Meski begitu, Mode Standar mengirim ribuan request (Nuclei dibatasi 15 per detik), jadi beri tahu admin website sebelum memeriksa.
- Hasil pemeriksaan berisi daftar kerawanan. Karena itu, `database/database.sqlite`, file Excel hasil export, dan Laporan Mentah termasuk **data sensitif**. Simpan di tempat aman dan jangan dibagikan ke publik.
- `.env` berisi kunci aplikasi dan kunci ZAP, jadi jangan dibagikan.
- SIPRIKA hanya bisa dibuka dari laptop itu sendiri (127.0.0.1). Jangan menjalankan `siprika:serve --host=0.0.0.0` di jaringan yang tidak tepercaya.

---

## 13. Membagikan, memperbarui, dan memindahkan SIPRIKA

**Membuat zip untuk orang lain.** Dari laptop yang sudah berisi SIPRIKA, jalankan:

```
php artisan siprika:package
```

Zip berukuran sekitar 4,5 GB akan dibuat di samping folder SIPRIKA. Zip ini tidak berisi `.env` maupun database. Penerima tinggal mengikuti panduan ini.

**Memperbarui ke versi SIPRIKA yang lebih baru** sambil mempertahankan riwayat:

1. Tutup SIPRIKA.
2. Ekstrak versi baru ke folder terpisah.
3. Salin `.env` ke folder baru. Salin juga **semua** file `database\database.sqlite*` (termasuk `database.sqlite-wal` dan `database.sqlite-shm` jika ada) ke folder `database` yang baru.
4. Di Command Prompt pada folder baru, jalankan `php artisan siprika:install` untuk memperbarui struktur database. Setelah itu jalankan SIPRIKA seperti biasa dengan `jalankan-siprika.bat`.
5. (Opsional) Jalankan `php artisan siprika:recalculate --all` untuk menghitung ulang Risk Register dengan aturan terbaru, tanpa memindai ulang.

**Memperbarui template Nuclei.** Lakukan sebaiknya sebulan sekali:

```
wsl -d Ubuntu -e nuclei -ut
php artisan siprika:check-nuclei
```

---

## 14. Referensi cepat

| Perintah (di folder `siprika`) | Fungsi |
|---|---|
| `jalankan-siprika.bat` (klik dua kali) | Menjalankan SIPRIKA. Saat pertama kali, sekaligus melakukan persiapan |
| `php artisan siprika:install` | Persiapan awal. Aman diulang untuk melihat ringkasan pengaturan |
| `php artisan siprika:serve` | Menjalankan SIPRIKA dari Command Prompt. Tambahkan `--port=8001` untuk memakai port lain |
| `php artisan siprika:check-nuclei` | Mengecek template Nuclei setelah diperbarui |
| `php artisan siprika:recalculate --all` | Menghitung ulang Risk Register tanpa memindai ulang |
| `php artisan siprika:package` | Membuat zip untuk dibagikan |

| Port | Dipakai oleh |
|---|---|
| 8000 | Halaman SIPRIKA (http://127.0.0.1:8000) |
| 8080 | OWASP ZAP |
| 8081 | AI (llama-server) |

| File | Isi |
|---|---|
| `.env` | Pengaturan |
| `database/database.sqlite` | Riwayat dan hasil pemeriksaan |
| `storage/logs/laravel.log` | Catatan kesalahan |
