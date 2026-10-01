<?php

namespace App\Jobs;

use App\Enums\ScanTargetStatus;
use App\Models\ScanTarget;
use App\Scanner\Network\NetworkMonitor;
use App\Scanner\ScanOrchestrator;
use DateTimeInterface;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use Illuminate\Queue\Middleware\WithoutOverlapping;
use Illuminate\Support\Facades\Log;
use Throwable;

/**
 * Memeriksa satu website. Hanya satu website diperiksa dalam satu waktu (bagian 26).
 */
class ProcessScanTarget implements ShouldQueue
{
    use Queueable;

    public const REQUEUED_MESSAGE = 'Koneksi internet laptop terputus saat website ini diperiksa. Hasilnya dibuang dan website diperiksa ulang otomatis di akhir antrean.';

    public const NETWORK_LOST_MESSAGE = 'Koneksi internet laptop terputus lagi saat website ini diperiksa ulang, sehingga pemeriksaan yang ERROR belum tentu disebabkan website. Pindai ulang setelah koneksi stabil.';

    /**
     * Gagal langsung saat terjadi exception. Pelepasan ulang karena menunggu antrean tidak dihitung.
     */
    public int $maxExceptions = 1;

    /**
     * Batas waktu dijaga di dalam ScanOrchestrator karena opsi --timeout worker tidak berfungsi di Windows.
     */
    public int $timeout = 0;

    /**
     * Website yang riwayatnya sudah dihapus (contoh target dibatalkan lalu batch dihapus) dilewati tanpa dicatat gagal.
     */
    public bool $deleteWhenMissingModels = true;

    /**
     * Website ini sudah dimasukkan lagi ke antrean karena koneksi laptop terputus saat diperiksa. Hanya satu kali.
     */
    public bool $requeued = false;

    public function __construct(public ScanTarget $target) {}

    /**
     * @return array<int, object>
     */
    public function middleware(): array
    {
        return [self::overlap()];
    }

    /**
     * Kunci supaya hanya satu website diperiksa dalam satu waktu. Job lain dilepas ulang setiap 10 detik.
     */
    private static function overlap(): WithoutOverlapping
    {
        return (new WithoutOverlapping('siprika-scanner'))
            ->releaseAfter(10)
            // Termasuk waktu menunggu koneksi internet sebelum website diperiksa
            ->expireAfter((int) config('siprika.scan.target_timeout') + (int) config('siprika.scan.offline_wait') + 600);
    }

    /**
     * Nama kunci cache untuk ScanRecovery, yang melepas kunci milik worker yang sudah berhenti.
     */
    public static function overlapLockKey(): string
    {
        return self::overlap()->getLockKey(new self(new ScanTarget));
    }

    public function retryUntil(): DateTimeInterface
    {
        return now()->addDay();
    }

    public function handle(ScanOrchestrator $orchestrator, NetworkMonitor $network): void
    {
        $this->target->refresh();

        // Target yang dibatalkan atau sudah diproses dilewati
        if ($this->target->status !== ScanTargetStatus::Queued) {
            return;
        }

        // Laptop offline (contoh Wi-Fi terputus): antrean dijeda sampai koneksi kembali, supaya website ini dan website
        // berikutnya tidak ikut gagal. Lewat batas waktu, website tetap diperiksa dan dicatat DNS gagal.
        $online = $network->waitUntilOnline($this->target);

        // Dibatalkan saat menunggu koneksi
        if ($this->target->refresh()->status !== ScanTargetStatus::Queued) {
            return;
        }

        $this->target->update([
            'status' => ScanTargetStatus::Running,
            'started_at' => now(),
            'error_message' => null,
        ]);

        $context = $orchestrator->run($this->target);

        $this->target->update(['finished_at' => now()]);

        // Koneksi terputus di tengah pemeriksaan. Website yang sudah offline sejak sebelum mulai tidak dihitung,
        // karena antrean sudah menunggu koneksi sampai batas waktu.
        if ($online && $this->target->status !== ScanTargetStatus::Completed && ($context->networkLost || ! $network->isOnline($this->target->host))) {
            $this->handleNetworkLoss();
        }
    }

    /**
     * ERROR karena koneksi laptop terputus bukan berasal dari website. Hasilnya dibuang dan website dimasukkan lagi ke
     * akhir antrean satu kali; website berikutnya menunggu koneksi kembali. Jika terputus lagi, hasil disimpan dengan catatan.
     */
    private function handleNetworkLoss(): void
    {
        Log::warning('SIPRIKA koneksi internet terputus saat memeriksa', ['target' => $this->target->url, 'diperiksa_ulang' => ! $this->requeued]);

        if ($this->requeued) {
            $this->target->update(['error_message' => $this->target->error_message ?? self::NETWORK_LOST_MESSAGE]);

            return;
        }

        $this->target->resetResults(self::REQUEUED_MESSAGE);

        $job = new self($this->target);
        $job->requeued = true;
        dispatch($job);
    }

    public function failed(?Throwable $exception): void
    {
        $this->target->refresh();

        if ($this->target->status->isFinished()) {
            return;
        }

        $this->target->update([
            'status' => ScanTargetStatus::Failed,
            'error_message' => 'Pemeriksaan berhenti karena kesalahan sistem: '.mb_substr((string) $exception?->getMessage(), 0, 500),
            'finished_at' => now(),
        ]);
    }
}
