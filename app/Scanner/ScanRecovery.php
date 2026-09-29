<?php

namespace App\Scanner;

use App\Enums\ScanTargetStatus;
use App\Jobs\ProcessScanTarget;
use App\Models\ScanTarget;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\File;

/**
 * Memulihkan antrean setelah SIPRIKA dihentikan saat pemeriksaan berjalan (contoh Ctrl+C pada siprika:serve).
 * Website yang masih RUNNING ditandai FAILED karena worker yang memeriksanya sudah berhenti, dan kunci
 * "satu website sekaligus" dilepas supaya antrean berikutnya tidak menunggu kunci kedaluwarsa (hampir 1 jam).
 * Folder kerja tool yang tertinggal (berisi output dan log request tool) juga dihapus.
 * Dijalankan siprika:serve sebelum queue worker dimulai, saat belum ada pemeriksaan yang berjalan.
 */
class ScanRecovery
{
    public const MESSAGE = 'Pemeriksaan terhenti karena SIPRIKA dihentikan saat website ini diperiksa. Gunakan tombol Pindai Ulang untuk memeriksa lagi.';

    /**
     * @return int jumlah website yang ditandai terhenti
     */
    public function recover(): int
    {
        $stopped = ScanTarget::where('status', ScanTargetStatus::Running->value)->get();

        foreach ($stopped as $target) {
            $target->update([
                'status' => ScanTargetStatus::Failed,
                'error_message' => self::MESSAGE,
                'finished_at' => now(),
            ]);
        }

        Cache::lock(ProcessScanTarget::overlapLockKey())->forceRelease();
        $this->removeStaleWorkDirectories();

        return $stopped->count();
    }

    /**
     * Folder kerja tool (storage/app/private/scans) yang lebih tua dari batas waktu pemeriksaan terlama pasti sudah
     * tidak dipakai. Folder yang lebih baru dibiarkan, karena mungkin milik pemeriksaan yang sedang berjalan.
     *
     * @return int jumlah folder yang dihapus
     */
    public function removeStaleWorkDirectories(): int
    {
        $scans = storage_path('app/private/scans');

        // Instalasi baru: folder dibuat saat tool pertama kali dijalankan
        if (! File::isDirectory($scans)) {
            return 0;
        }

        $threshold = time() - (int) config('siprika.scan.target_timeout') - 600;
        $removed = 0;

        foreach (File::directories($scans) as $directory) {
            if (File::lastModified($directory) < $threshold) {
                File::deleteDirectory($directory);
                $removed++;
            }
        }

        return $removed;
    }
}
