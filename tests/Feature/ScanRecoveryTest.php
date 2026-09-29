<?php

namespace Tests\Feature;

use App\Enums\ScanMode;
use App\Enums\ScanTargetStatus;
use App\Jobs\ProcessScanTarget;
use App\Models\ScanBatch;
use App\Scanner\ScanRecovery;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\File;
use Tests\TestCase;

/**
 * Pemulihan antrean setelah SIPRIKA dihentikan saat pemeriksaan berjalan.
 */
class ScanRecoveryTest extends TestCase
{
    use RefreshDatabase;

    public function test_website_yang_terhenti_ditandai_gagal_dan_kunci_antrean_dilepas(): void
    {
        $batch = ScanBatch::create(['mode' => ScanMode::Quick]);
        $running = $batch->targets()->create(['position' => 1, 'url' => 'https://a.jemberkab.go.id', 'host' => 'a.jemberkab.go.id', 'status' => ScanTargetStatus::Running]);
        $queued = $batch->targets()->create(['position' => 2, 'url' => 'https://b.jemberkab.go.id', 'host' => 'b.jemberkab.go.id']);
        $done = $batch->targets()->create(['position' => 3, 'url' => 'https://c.jemberkab.go.id', 'host' => 'c.jemberkab.go.id', 'status' => ScanTargetStatus::Completed]);

        // Kunci milik worker yang sudah berhenti masih tersimpan di cache
        $this->assertTrue(Cache::lock(ProcessScanTarget::overlapLockKey(), 3300)->get());

        $this->assertSame(1, app(ScanRecovery::class)->recover());

        $running->refresh();
        $this->assertSame(ScanTargetStatus::Failed, $running->status);
        $this->assertSame(ScanRecovery::MESSAGE, $running->error_message);
        $this->assertNotNull($running->finished_at);
        $this->assertSame(ScanTargetStatus::Queued, $queued->fresh()->status);
        $this->assertSame(ScanTargetStatus::Completed, $done->fresh()->status);

        // Antrean berikutnya bisa langsung mendapat kunci
        $this->assertTrue(Cache::lock(ProcessScanTarget::overlapLockKey(), 3300)->get());
    }

    public function test_job_ulang_untuk_website_yang_sudah_ditandai_gagal_tidak_memeriksa_lagi(): void
    {
        $batch = ScanBatch::create(['mode' => ScanMode::Quick]);
        $target = $batch->targets()->create(['position' => 1, 'url' => 'https://a.jemberkab.go.id', 'host' => 'a.jemberkab.go.id', 'status' => ScanTargetStatus::Running]);
        app(ScanRecovery::class)->recover();

        // Job yang tertinggal di antrean dijalankan ulang setelah retry_after
        ProcessScanTarget::dispatchSync($target);

        $this->assertSame(ScanTargetStatus::Failed, $target->fresh()->status);
        $this->assertSame(0, $target->observations()->count());
    }

    public function test_folder_kerja_tool_yang_tertinggal_dihapus_tetapi_yang_mungkin_dipakai_dibiarkan(): void
    {
        $scans = storage_path('app/private/scans');
        $stale = $scans.'/nuclei-test-lama-'.uniqid();
        $fresh = $scans.'/nuclei-test-baru-'.uniqid();
        File::ensureDirectoryExists($stale);
        File::ensureDirectoryExists($fresh);
        file_put_contents($stale.'/nuclei-errors-1.jsonl', '{}');
        touch($stale, time() - (int) config('siprika.scan.target_timeout') - 3600);

        try {
            app(ScanRecovery::class)->recover();

            $this->assertDirectoryDoesNotExist($stale);
            $this->assertDirectoryExists($fresh, 'Folder baru mungkin milik pemeriksaan yang sedang berjalan');
        } finally {
            File::deleteDirectory($stale);
            File::deleteDirectory($fresh);
        }
    }

    public function test_pemulihan_tetap_jalan_pada_instalasi_baru_tanpa_folder_kerja(): void
    {
        $this->app->useStoragePath(storage_path('framework/testing/siprika-baru-'.uniqid()));

        $this->assertSame(0, app(ScanRecovery::class)->removeStaleWorkDirectories());
        $this->assertSame(0, app(ScanRecovery::class)->recover());
    }
}
