<?php

namespace App\Scanner\Checks;

use App\Scanner\ScanContext;

/**
 * Pemeriksaan lama yang dapat berjalan di latar belakang sementara pemeriksaan berikutnya dikerjakan,
 * contoh Nuclei yang dibatasi 15 request per detik (bagian 26). Tetap satu website dalam satu waktu.
 */
interface BackgroundCheck extends Check
{
    /**
     * Mulai pemeriksaan tanpa menunggu hasilnya. Jika tidak dapat dimulai, observation langsung dicatat.
     */
    public function start(ScanContext $context): void;

    /**
     * Sudah dimulai dan hasilnya belum dibaca.
     */
    public function isPending(): bool;

    /**
     * Baca output yang sudah ada tanpa menunggu, dipanggil di antara pemeriksaan lain.
     */
    public function poll(): void;

    /**
     * Tunggu sampai selesai, lalu catat observation dan finding.
     */
    public function finish(ScanContext $context): void;
}
