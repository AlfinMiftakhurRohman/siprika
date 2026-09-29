<?php

namespace Tests\Feature;

use App\Enums\ScanMode;
use App\Enums\ScanTargetStatus;
use App\Enums\Severity;
use App\Http\Controllers\ScanTargetController;
use App\Models\ScanBatch;
use App\Models\ScanTarget;
use App\Scanner\ScanProgress;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\Support\FakeNetwork;
use Tests\Support\InteractsWithScanner;
use Tests\TestCase;

/**
 * Semua halaman tetap tampil untuk setiap status pemeriksaan, id yang tidak ada, dan data kosong.
 */
class PageStatesTest extends TestCase
{
    use InteractsWithScanner;
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        $this->setUpScanner();
    }

    /**
     * Website hasil pemeriksaan sungguhan (jaringan palsu), lengkap dengan temuan dan Risk Register.
     */
    private function scannedTarget(?ScanBatch $batch = null, string $host = 'web.jemberkab.go.id'): ScanTarget
    {
        FakeNetwork::http([
            "https://{$host}/" => Http::response('<html><head><title>Dinas Contoh</title></head></html>', 200, ['Server' => 'Apache/2.4.41']),
            "http://{$host}/" => Http::response('<title>Dinas Contoh</title>', 200),
            "https://{$host}/.env" => Http::response("APP_KEY=base64:rahasia\nDB_PASSWORD=rahasia\n", 200),
        ]);

        return $this->scan("https://{$host}", $batch);
    }

    private function targetWithStatus(ScanTargetStatus $status): ScanTarget
    {
        if (in_array($status, [ScanTargetStatus::Completed, ScanTargetStatus::Partial, ScanTargetStatus::Failed], true)) {
            $target = $this->scannedTarget();
            $target->update([
                'status' => $status,
                'error_message' => $status === ScanTargetStatus::Failed ? 'Website tidak dapat diakses.' : null,
            ]);

            return $target;
        }

        $batch = ScanBatch::create(['mode' => ScanMode::Standard]);
        $target = $batch->targets()->create(['position' => 1, 'url' => 'https://web.jemberkab.go.id', 'host' => 'web.jemberkab.go.id', 'status' => $status]);

        if ($status === ScanTargetStatus::Running) {
            $now = microtime(true);
            $target->update([
                'started_at' => now()->subMinutes(3),
                'progress' => [
                    ['key' => 'http-info', 'label' => 'Informasi HTTP', 'status' => ScanProgress::DONE, 'weight' => 5, 'started_at' => $now - 180],
                    ['key' => 'nuclei', 'label' => 'Nuclei', 'status' => ScanProgress::RUNNING, 'weight' => 1300, 'started_at' => $now - 170],
                    ['key' => 'testssl', 'label' => 'testssl.sh', 'status' => ScanProgress::RUNNING, 'weight' => 80, 'started_at' => $now - 20],
                    ['key' => 'ai-analysis', 'label' => 'AI Analysis', 'status' => ScanProgress::WAITING, 'weight' => 60],
                ],
            ]);
        }

        if ($status === ScanTargetStatus::Cancelled) {
            $target->update(['finished_at' => now()]);
        }

        return $target;
    }

    /**
     * @return array<string, array{ScanTargetStatus}>
     */
    public static function statusProvider(): array
    {
        $cases = [];

        foreach (ScanTargetStatus::cases() as $status) {
            $cases[$status->label()] = [$status];
        }

        return $cases;
    }

    #[DataProvider('statusProvider')]
    public function test_semua_halaman_dan_tab_tampil_untuk_setiap_status(ScanTargetStatus $status): void
    {
        $target = $this->targetWithStatus($status);

        foreach (array_keys(ScanTargetController::TABS) as $tab) {
            $this->get(route('targets.show', ['scanTarget' => $target, 'tab' => $tab]))
                ->assertOk()
                ->assertSee($target->host)
                ->assertSee($status->label());
        }

        $this->get(route('scans.show', $target->batch))->assertOk()->assertSee($target->host);
        $this->get(route('scans.risk-register', $target->batch))->assertOk();
        $this->get(route('scans.create'))->assertOk()->assertSee('#'.$target->scan_batch_id);
        $this->get(route('scans.index'))->assertOk()->assertSee('#'.$target->scan_batch_id);
        $this->get(route('targets.raw-report', $target))->assertOk()->assertDownload();

        $this->get(route('scans.progress', $target->batch))
            ->assertOk()
            ->assertJsonPath('targets.0.status', $status->value)
            ->assertJsonPath('finished', $status->isFinished());
    }

    public function test_website_yang_sedang_diperiksa_menampilkan_semua_tahap_yang_berjalan(): void
    {
        $target = $this->targetWithStatus(ScanTargetStatus::Running);

        $progress = $this->get(route('scans.progress', $target->batch))->assertOk()->json('targets.0');

        $this->assertSame('Nuclei + testssl.sh', $progress['step']);
        $this->assertGreaterThan(0, $progress['percent']);
        $this->assertLessThan(100, $progress['percent']);
    }

    public function test_hasil_lengkap_tampil_di_setiap_tab(): void
    {
        $target = $this->targetWithStatus(ScanTargetStatus::Completed);
        $this->assertGreaterThan(0, $target->findings()->count());
        $this->assertGreaterThan(0, $target->riskItems()->count());

        $this->get(route('targets.show', ['scanTarget' => $target, 'tab' => 'findings']))->assertOk()->assertSee('/.env');
        $this->get(route('targets.show', ['scanTarget' => $target, 'tab' => 'risk']))->assertOk()->assertSee('Not Acceptable');
        $this->get(route('targets.show', ['scanTarget' => $target, 'tab' => 'coverage']))->assertOk()->assertSee('FAIL');
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function missingRouteProvider(): array
    {
        return [
            'halaman batch' => ['get', 'scans.show'],
            'progress' => ['get', 'scans.progress'],
            'risk register batch' => ['get', 'scans.risk-register'],
            'export batch' => ['get', 'scans.export'],
            'laporan mentah batch' => ['get', 'scans.raw-report'],
            'batalkan' => ['post', 'scans.cancel'],
            'pindai ulang batch' => ['post', 'scans.rescan'],
            'halaman website' => ['get', 'targets.show'],
            'export website' => ['get', 'targets.export'],
            'laporan mentah website' => ['get', 'targets.raw-report'],
            'pindai ulang website' => ['post', 'targets.rescan'],
        ];
    }

    #[DataProvider('missingRouteProvider')]
    public function test_id_yang_tidak_ada_mengembalikan_404(string $method, string $route): void
    {
        $this->{$method}(route($route, 999))->assertNotFound();
        $this->{$method}(str_replace('999', 'abc', route($route, 999)))->assertNotFound();
        $this->assertSame(0, ScanBatch::count(), 'Tidak ada batch baru yang dibuat');
    }

    public function test_progress_batch_yang_tidak_ada_dijawab_json(): void
    {
        $this->getJson(route('scans.progress', 999))->assertNotFound()->assertJsonStructure(['message']);
    }

    public function test_tab_tidak_dikenal_kembali_ke_overview(): void
    {
        $target = $this->targetWithStatus(ScanTargetStatus::Completed);

        foreach (['tidak-ada', '', 'OVERVIEW'] as $tab) {
            $this->get(route('targets.show', ['scanTarget' => $target, 'tab' => $tab]))->assertOk()->assertSee('Teknologi');
        }

        $this->get(route('targets.show', $target).'?tab[]=findings')->assertOk()->assertSee('Teknologi');
    }

    public function test_export_tanpa_risiko_tetap_menghasilkan_file_excel(): void
    {
        $target = $this->targetWithStatus(ScanTargetStatus::Queued);

        $downloads = [
            "Risk Register SIPRIKA - Batch {$target->scan_batch_id}.xlsx" => route('scans.export', $target->batch),
            'Risk Register SIPRIKA - web.jemberkab.go.id.xlsx' => route('targets.export', $target),
        ];

        foreach ($downloads as $filename => $url) {
            $response = $this->get($url)->assertOk()->assertDownload($filename);
            $this->assertGreaterThan(10_000, $response->baseResponse->getFile()->getSize());
        }
    }

    public function test_progress_tidak_membuat_session_sedangkan_halaman_biasa_tetap_memakai_session(): void
    {
        $target = $this->targetWithStatus(ScanTargetStatus::Running);

        $this->get(route('scans.progress', $target->batch))
            ->assertOk()
            ->assertCookieMissing(config('session.cookie'))
            ->assertCookieMissing('XSRF-TOKEN');

        $this->get(route('scans.show', $target->batch))
            ->assertOk()
            ->assertCookie(config('session.cookie'), null, false);
    }

    private function queryCount(string $url): int
    {
        DB::flushQueryLog();
        DB::enableQueryLog();
        $this->get($url)->assertOk();
        $count = count(DB::getQueryLog());
        DB::disableQueryLog();

        return $count;
    }

    public function test_jumlah_query_halaman_tidak_bertambah_dengan_jumlah_data(): void
    {
        $batch = ScanBatch::create(['mode' => ScanMode::Quick]);
        $first = $this->scannedTarget($batch);

        $pages = fn () => [
            'beranda' => $this->queryCount(route('scans.create')),
            'riwayat' => $this->queryCount(route('scans.index')),
            'batch' => $this->queryCount(route('scans.show', $batch)),
            'risk register' => $this->queryCount(route('scans.risk-register', $batch)),
            'findings' => $this->queryCount(route('targets.show', ['scanTarget' => $first, 'tab' => 'findings'])),
            'coverage' => $this->queryCount(route('targets.show', ['scanTarget' => $first, 'tab' => 'coverage'])),
            'risk website' => $this->queryCount(route('targets.show', ['scanTarget' => $first, 'tab' => 'risk'])),
        ];

        $before = $pages();

        // Data bertambah: website lain, batch lain, dan temuan lain pada website yang sama
        $this->scannedTarget($batch, 'lain.jemberkab.go.id');
        $this->scannedTarget(null, 'dinas.jemberkab.go.id');

        foreach (range(1, 5) as $index) {
            $finding = $first->findings()->create(['finding_key' => "nuclei:contoh-{$index}", 'title' => "Contoh {$index}", 'severity' => Severity::Medium, 'sources' => ['nuclei']]);
            $finding->evidences()->create(['source' => 'nuclei', 'detail' => "Bukti {$index}", 'endpoint' => "https://web.jemberkab.go.id/{$index}"]);
        }

        $this->assertSame($before, $pages());
    }
}
