@echo off
rem Menjalankan SIPRIKA (web, antrean, AI, dan ZAP) dengan klik dua kali.
rem Biarkan jendela ini terbuka selama memakai SIPRIKA. Tutup jendela atau tekan Ctrl+C untuk berhenti.
title SIPRIKA - jangan ditutup selama pemeriksaan berjalan
cd /d "%~dp0"

where php >nul 2>nul
if errorlevel 1 (
    echo PHP tidak ditemukan. Pasang PHP 8.3 dan tambahkan ke PATH, lihat PANDUAN.md bagian Memasang PHP.
    pause
    exit /b 1
)

rem Pertama kali dipakai (belum ada .env atau database): buat .env, APP_KEY, dan database
set PERLU_INSTAL=
if not exist ".env" set PERLU_INSTAL=1
if not exist "database\database.sqlite" set PERLU_INSTAL=1
if defined PERLU_INSTAL (
    echo Persiapan pertama SIPRIKA...
    php artisan siprika:install
    if errorlevel 1 (
        echo.
        echo Persiapan gagal. Perbaiki masalah di atas, lalu klik dua kali file ini lagi.
        pause
        exit /b 1
    )
)

rem Browser dibuka setelah web server siap
start "" /min cmd /c "timeout /t 8 /nobreak >nul & start http://127.0.0.1:8000"

php artisan siprika:serve

echo.
echo SIPRIKA berhenti.
echo Jika muncul "Port 8000 sudah dipakai", SIPRIKA sudah berjalan di jendela lain: buka http://127.0.0.1:8000
pause
