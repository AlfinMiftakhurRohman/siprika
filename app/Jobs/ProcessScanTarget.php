<?php

namespace App\Jobs;

use App\Enums\ScanTargetStatus;
use App\Models\ScanTarget;
use App\Scanner\ScanOrchestrator;
use DateTimeInterface;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use Illuminate\Queue\Middleware\WithoutOverlapping;
use Throwable;

/**
 * Memeriksa satu website. Hanya satu website diperiksa dalam satu waktu (bagian 26).
 */
class ProcessScanTarget implements ShouldQueue
{
    use Queueable;

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
            ->expireAfter((int) config('siprika.scan.target_timeout') + 600);
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

    public function handle(ScanOrchestrator $orchestrator): void
    {
        $this->target->refresh();

        // Target yang dibatalkan atau sudah diproses dilewati
        if ($this->target->status !== ScanTargetStatus::Queued) {
            return;
        }

        $this->target->update([
            'status' => ScanTargetStatus::Running,
            'started_at' => now(),
            'error_message' => null,
        ]);

        $orchestrator->run($this->target);

        $this->target->update(['finished_at' => now()]);
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
