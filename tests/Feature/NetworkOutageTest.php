<?php

namespace Tests\Feature;

use App\Enums\ObservationStatus;
use App\Enums\ScanMode;
use App\Enums\ScanTargetStatus;
use App\Jobs\ProcessScanTarget;
use App\Models\ScanBatch;
use App\Models\ScanTarget;
use App\Scanner\ScanRecovery;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Process;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Sleep;
use Tests\Support\FakeNetwork;
use Tests\Support\InteractsWithScanner;
use Tests\TestCase;

/**
 * Koneksi internet laptop terputus (contoh Wi-Fi putus): antrean menunggu koneksi kembali, website yang terputus di
 * tengah pemeriksaan diperiksa ulang satu kali, dan website yang gagal dapat diperiksa ulang di batch yang sama.
 */
class NetworkOutageTest extends TestCase
{
    use InteractsWithScanner;
    use RefreshDatabase;

    private const HOME = 'https://web.jemberkab.go.id/';

    protected function setUp(): void
    {
        parent::setUp();

        $this->setUpScanner();
        Sleep::fake();
        config(['siprika.scan.offline_wait' => 1800]);

        FakeNetwork::http([
            self::HOME => Http::response('<title>Web</title>', 200, self::secureHeaders()),
            'http://web.jemberkab.go.id/' => Http::response('', 301, ['Location' => self::HOME]),
        ]);
    }

    private function queuedTarget(): ScanTarget
    {
        return ScanBatch::create(['mode' => ScanMode::Standard])->targets()->create([
            'position' => 1, 'url' => 'https://web.jemberkab.go.id', 'host' => 'web.jemberkab.go.id',
        ]);
    }

    /**
     * Jalankan job langsung, supaya job yang dimasukkan lagi ke antrean tercatat Queue::fake
     * (dispatch_sync juga ikut ditahan Queue::fake).
     */
    private function process(ScanTarget $target, bool $requeued = false): ScanTarget
    {
        $job = new ProcessScanTarget($target);
        $job->requeued = $requeued;
        app()->call([$job, 'handle']);

        return $target->fresh();
    }

    /**
     * Wi-Fi terputus setelah halaman utama terbaca: permintaan berikutnya gagal dan server DNS tidak dapat dihubungi.
     */
    private function dropConnectionAfterHomepage(): void
    {
        FakeNetwork::http([
            self::HOME => Http::response('<title>Web</title>', 200, self::secureHeaders()),
            'http://web.jemberkab.go.id/' => Http::response('', 301, ['Location' => self::HOME]),
            self::HOME.'*' => function () {
                $this->network->offline = true;

                return 'refused';
            },
        ]);
    }

    public function test_antrean_menunggu_koneksi_internet_lalu_website_diperiksa_normal(): void
    {
        $this->network->offline = true;
        $steps = [];

        // Koneksi kembali setelah dua kali pengecekan; selama menunggu, progress menampilkan alasannya
        Sleep::whenFakingSleep(function () use (&$steps) {
            $steps[] = ScanTarget::sole()->currentStep();
            $this->network->offline = count($steps) < 2;
        });

        $target = $this->scan();

        $this->assertSame(ScanTargetStatus::Completed, $target->status);
        $this->assertCount(2, $steps);
        $this->assertStringStartsWith('Menunggu koneksi internet (terputus sejak ', $steps[0]);
        $this->assertNotContains('network-wait', array_column($target->progress, 'key'));
        Sleep::assertSleptTimes(2);
    }

    public function test_website_yang_dibatalkan_saat_menunggu_koneksi_tidak_diperiksa(): void
    {
        $this->network->offline = true;
        Sleep::whenFakingSleep(fn () => ScanTarget::sole()->update(['status' => ScanTargetStatus::Cancelled]));

        $target = $this->scan();

        $this->assertSame(ScanTargetStatus::Cancelled, $target->status);
        $this->assertNull($target->progress);
        $this->assertNull($target->started_at);
        $this->assertSame(0, $target->observations()->count());
        Http::assertNothingSent();
    }

    public function test_lewat_batas_menunggu_website_dicatat_dns_gagal_tanpa_diperiksa_ulang(): void
    {
        config(['siprika.scan.offline_wait' => 30]);
        Queue::fake();
        $this->network->offline = true;

        $target = $this->process($this->queuedTarget());

        // Dicek setiap 15 detik sampai batas 30 detik, lalu tetap diperiksa
        Sleep::assertSleptTimes(2);
        $this->assertSame(ScanTargetStatus::Failed, $target->status);
        $this->assertStringContainsString('DNS gagal', $target->error_message);
        $this->assertNotContains('network-wait', array_column($target->progress, 'key'));
        Queue::assertNothingPushed();
    }

    public function test_koneksi_terputus_di_tengah_pemeriksaan_website_dimasukkan_lagi_ke_antrean(): void
    {
        Queue::fake();
        $this->dropConnectionAfterHomepage();

        $target = $this->process($this->queuedTarget());

        // Hasil yang terpengaruh koneksi dibuang, website diperiksa ulang di akhir antrean
        $this->assertSame(ScanTargetStatus::Queued, $target->status);
        $this->assertSame(ProcessScanTarget::REQUEUED_MESSAGE, $target->error_message);
        $this->assertSame(0, $target->observations()->count());
        $this->assertNull($target->started_at);
        $this->assertNull($target->progress);
        Queue::assertPushed(ProcessScanTarget::class, fn (ProcessScanTarget $job) => $job->requeued && $job->target->is($target));
    }

    public function test_website_yang_sudah_diperiksa_ulang_tidak_dimasukkan_lagi_ke_antrean(): void
    {
        Queue::fake();
        $this->dropConnectionAfterHomepage();

        $target = $this->process($this->queuedTarget(), requeued: true);

        $this->assertSame(ScanTargetStatus::Partial, $target->status);
        $this->assertSame(ProcessScanTarget::NETWORK_LOST_MESSAGE, $target->error_message);
        $this->assertTrue($target->observations->contains('status', ObservationStatus::Error));
        Queue::assertNothingPushed();
    }

    public function test_website_yang_menolak_koneksi_tidak_dianggap_koneksi_laptop_terputus(): void
    {
        Queue::fake();
        FakeNetwork::http([self::HOME => 'refused', 'http://web.jemberkab.go.id/' => 'refused']);

        $target = $this->process($this->queuedTarget());

        $this->assertSame(ScanTargetStatus::Failed, $target->status);
        $this->assertStringContainsString('Website tidak dapat diakses', $target->error_message);
        Queue::assertNothingPushed();
    }

    public function test_dns_yang_tidak_merespons_sebelum_tool_dijalankan_dicatat_koneksi_terputus(): void
    {
        config(['siprika.tools.whatweb.command' => 'whatweb']);
        Process::fake();
        // DNS menjawab saat validasi, lalu tidak merespons sama sekali (Wi-Fi putus sebelum WhatWeb dijalankan)
        $lookups = 0;
        $this->network->dns['web.jemberkab.go.id'] = function () use (&$lookups) {
            return ++$lookups === 1 ? ['93.184.216.34'] : throw FakeNetwork::dnsFailure();
        };

        $target = $this->scan(requeued: true);

        $whatweb = $target->observations->firstWhere('check_key', 'whatweb');
        $this->assertSame(ObservationStatus::Error, $whatweb->status);
        $this->assertStringContainsString('koneksi internet laptop terputus', $whatweb->summary);
        $this->assertSame(ProcessScanTarget::NETWORK_LOST_MESSAGE, $target->error_message);
        Process::assertNothingRan();
    }

    public function test_pindai_ulang_yang_gagal_memeriksa_ulang_website_gagal_dan_sebagian_gagal_di_batch_yang_sama(): void
    {
        // Halaman tanpa header keamanan: ada temuan dan item Risk Register yang harus ikut dibuang
        FakeNetwork::http([self::HOME => Http::response('<title>Web</title>', 200)]);
        $batch = ScanBatch::create(['mode' => ScanMode::Standard]);
        $partial = $this->scan(batch: $batch);
        $partial->update(['status' => ScanTargetStatus::Partial]);
        $completed = $batch->targets()->create(['position' => 2, 'url' => 'https://a.jemberkab.go.id', 'host' => 'a.jemberkab.go.id', 'status' => ScanTargetStatus::Completed]);
        $failed = $batch->targets()->create(['position' => 3, 'url' => 'https://b.jemberkab.go.id', 'host' => 'b.jemberkab.go.id', 'status' => ScanTargetStatus::Failed, 'error_message' => 'DNS gagal: server DNS tidak merespons.']);
        $this->assertGreaterThan(0, $partial->riskItems()->count());

        $this->get(route('scans.show', $batch))->assertOk()->assertSee('Pindai Ulang yang Gagal (2)');

        Queue::fake();
        $this->post(route('scans.retry-failed', $batch))
            ->assertRedirect(route('scans.show', $batch))
            ->assertSessionHas('status', '2 website yang gagal atau sebagian gagal dimasukkan lagi ke antrean batch ini.');

        foreach ([$partial, $failed] as $target) {
            $target->refresh();
            $this->assertSame(ScanTargetStatus::Queued, $target->status);
            $this->assertNull($target->error_message);
            $this->assertSame(0, $target->observations()->count());
            $this->assertSame(0, $target->findings()->count());
            $this->assertSame(0, $target->riskItems()->count());
            Queue::assertPushed(ProcessScanTarget::class, fn (ProcessScanTarget $job) => $job->target->is($target));
        }

        Queue::assertPushed(ProcessScanTarget::class, 2);
        $this->assertSame(ScanTargetStatus::Completed, $completed->fresh()->status);

        // Batch berjalan lagi, tombol tidak ditampilkan sampai selesai
        $this->get(route('scans.show', $batch))->assertOk()->assertDontSee('Pindai Ulang yang Gagal');
    }

    public function test_pindai_ulang_yang_gagal_ditolak_selama_batch_berjalan(): void
    {
        Queue::fake();
        $batch = ScanBatch::create(['mode' => ScanMode::Standard]);
        $failed = $batch->targets()->create(['position' => 1, 'url' => 'https://a.jemberkab.go.id', 'host' => 'a.jemberkab.go.id', 'status' => ScanTargetStatus::Failed]);
        $batch->targets()->create(['position' => 2, 'url' => 'https://b.jemberkab.go.id', 'host' => 'b.jemberkab.go.id', 'status' => ScanTargetStatus::Running]);

        $this->post(route('scans.retry-failed', $batch))
            ->assertRedirect(route('scans.show', $batch))
            ->assertSessionHas('status', fn (string $status) => str_contains($status, 'masih berjalan'));

        $this->assertSame(ScanTargetStatus::Failed, $failed->fresh()->status);
        Queue::assertNothingPushed();
    }

    public function test_catatan_menunggu_koneksi_dari_worker_yang_berhenti_dihapus_saat_pemulihan(): void
    {
        $target = $this->queuedTarget();
        $target->update(['progress' => [['key' => 'network-wait', 'label' => 'Menunggu koneksi internet (terputus sejak 18:33:58)', 'status' => 'running']]]);

        app(ScanRecovery::class)->recover();

        $this->assertNull($target->fresh()->progress);
        $this->assertSame(ScanTargetStatus::Queued, $target->fresh()->status);
    }
}
