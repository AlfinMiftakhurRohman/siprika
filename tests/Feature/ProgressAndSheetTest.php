<?php

namespace Tests\Feature;

use App\Enums\ScanMode;
use App\Enums\ScanTargetStatus;
use App\Models\ScanBatch;
use App\Models\ScanTarget;
use App\Risk\RiskRegisterExporter;
use App\Risk\RiskRegisterSheet;
use App\Scanner\ScanProgress;
use App\Support\Duration;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Process;
use PhpOffice\PhpSpreadsheet\IOFactory;
use PhpOffice\PhpSpreadsheet\RichText\RichText;
use Tests\Support\FakeNetwork;
use Tests\Support\InteractsWithScanner;
use Tests\TestCase;

class ProgressAndSheetTest extends TestCase
{
    use InteractsWithScanner;
    use RefreshDatabase;

    private const HOME = 'https://web.jemberkab.go.id/';

    protected function setUp(): void
    {
        parent::setUp();

        $this->setUpScanner();
    }

    private function fakeVulnerableSite(): void
    {
        FakeNetwork::http([
            self::HOME => Http::response('<html><head><title>Dinas Contoh</title></head></html>', 200, ['Server' => 'Apache/2.4.41']),
            'http://web.jemberkab.go.id/' => Http::response('<title>Dinas Contoh</title>', 200),
            'https://web.jemberkab.go.id/.env' => Http::response("APP_KEY=base64:rahasia\nDB_PASSWORD=rahasia\n", 200),
        ]);
    }

    public function test_persentase_progress_adalah_waktu_berjalan_dibanding_perkiraan_seluruh_waktu(): void
    {
        $now = 1_000_000.0;
        $steps = [
            ['status' => ScanProgress::DONE, 'weight' => 10, 'started_at' => $now - 60],
            ['status' => ScanProgress::RUNNING, 'weight' => 100, 'started_at' => $now - 50],
            ['status' => ScanProgress::WAITING, 'weight' => 90],
        ];

        // Berjalan 60 detik, sisa 50 + 90 = 140 detik: 60 dari 200
        $this->assertSame(30, ScanProgress::percent($steps, $now));

        // Tahap yang lebih lama dari perkiraan menyisakan 5% bobotnya, persentase mendekati 99 tanpa melewatinya
        $steps[1]['started_at'] = $now - 10_000;
        $this->assertSame(99, ScanProgress::percent($steps, $now));

        // Semua tahap selesai tetap 99 sampai target benar-benar ditandai selesai
        $this->assertSame(99, ScanProgress::percent(array_map(fn ($s) => ['status' => ScanProgress::DONE] + $s, $steps), $now));
        $this->assertSame(0, ScanProgress::percent([], $now));

        // Belum ada tahap yang mulai: dari bobot tahap yang sudah selesai
        $this->assertSame(0, ScanProgress::percent([['status' => ScanProgress::WAITING, 'weight' => 10]], $now));
    }

    public function test_nuclei_di_latar_belakang_dihitung_bersamaan_dengan_tool_lain(): void
    {
        $now = 1_000_000.0;
        // Seperti Mode Standar: Nuclei berjalan sementara Nmap, testssl.sh, WhatWeb, dan ZAP dikerjakan
        $steps = [
            ['key' => 'http-info', 'status' => ScanProgress::DONE, 'weight' => 50, 'started_at' => $now - 60, 'finished_at' => $now - 40],
            ['key' => 'nuclei', 'status' => ScanProgress::RUNNING, 'weight' => 445, 'started_at' => $now - 40, 'background' => true],
            ['key' => 'ports', 'status' => ScanProgress::DONE, 'weight' => 15, 'started_at' => $now - 40, 'finished_at' => $now - 20],
            ['key' => 'testssl', 'status' => ScanProgress::RUNNING, 'weight' => 80, 'started_at' => $now - 20],
            ['key' => 'whatweb', 'status' => ScanProgress::WAITING, 'weight' => 10],
            ['key' => 'zap-passive', 'status' => ScanProgress::WAITING, 'weight' => 15],
            ['key' => 'ai-analysis', 'status' => ScanProgress::WAITING, 'weight' => 60, 'after_checks' => true],
            ['key' => 'risk-assessment', 'status' => ScanProgress::WAITING, 'weight' => 1, 'after_checks' => true],
        ];

        // Sisa Nuclei 405 lebih lama dari tool lain (60 + 10 + 15), lalu AI dan Risk Assessment 61
        $this->assertSame(405 + 61, ScanProgress::remainingSeconds($steps, $now));
        $this->assertSame((int) floor(60 / (60 + 466) * 100), ScanProgress::percent($steps, $now));

        // Nuclei selesai lebih dulu: yang tersisa tool lain lalu tahap penutup
        $steps[1]['status'] = ScanProgress::DONE;
        $this->assertSame(60 + 10 + 15 + 61, ScanProgress::remainingSeconds($steps, $now));

        // Data progress lama tanpa tanda background tetap dihitung berurutan
        $legacy = array_map(fn (array $step) => array_diff_key($step, ['background' => 1, 'after_checks' => 1]), $steps);
        $this->assertSame(60 + 10 + 15 + 60 + 1, ScanProgress::remainingSeconds($legacy, $now));
    }

    public function test_tahap_nuclei_dan_tahap_penutup_ditandai_saat_pemeriksaan_dimulai(): void
    {
        FakeNetwork::http([self::HOME => Http::response('<title>Web</title>', 200, self::secureHeaders())]);
        config(['siprika.tools.nuclei.command' => 'nuclei']);
        Process::fake(['*' => Process::result('')]);

        $steps = collect($this->scan()->progress)->keyBy('key');

        $this->assertTrue($steps['nuclei']['background']);
        $this->assertArrayNotHasKey('background', $steps['ports']);
        $this->assertTrue($steps['ai-analysis']['after_checks']);
        $this->assertTrue($steps['risk-assessment']['after_checks']);
    }

    public function test_bobot_tahap_mengikuti_mode_dan_tool_yang_dipasang(): void
    {
        FakeNetwork::http([self::HOME => Http::response('<title>Web</title>', 200, self::secureHeaders())]);

        $quick = collect($this->scan(mode: ScanMode::Quick)->progress)->keyBy('key');
        $this->assertSame(1, $quick['nuclei']['weight'], 'Nuclei belum dipasang, selesai seketika');
        $this->assertSame(1, $quick['ai-analysis']['weight'], 'AI tidak aktif');
        $this->assertSame(config('siprika.scan.expected_seconds.exposure.quick'), $quick['exposure']['weight']);
        $this->assertNotNull($quick['tls']['started_at']);

        config(['siprika.tools.nuclei.command' => 'nuclei']);
        $standard = collect($this->scan()->progress)->keyBy('key');
        $this->assertSame(config('siprika.scan.expected_seconds.nuclei.standard'), $standard['nuclei']['weight']);
    }

    public function test_endpoint_progress_mengirim_persentase_setiap_website(): void
    {
        $batch = ScanBatch::factory()->create();
        $queued = ScanTarget::factory()->for($batch, 'batch')->create(['position' => 1]);
        $running = ScanTarget::factory()->for($batch, 'batch')->create([
            'position' => 2,
            'status' => ScanTargetStatus::Running,
            'progress' => [
                ['key' => 'http-info', 'label' => 'Informasi HTTP', 'status' => ScanProgress::DONE, 'weight' => 50, 'started_at' => microtime(true) - 50],
                ['key' => 'nuclei', 'label' => 'Nuclei', 'status' => ScanProgress::RUNNING, 'weight' => 50, 'started_at' => microtime(true)],
            ],
        ]);
        $done = ScanTarget::factory()->for($batch, 'batch')->create(['position' => 3, 'status' => ScanTargetStatus::Completed]);

        $response = $this->getJson(route('scans.progress', $batch))->assertOk();

        $this->assertFalse($response->json('finished'));
        $targets = collect($response->json('targets'))->keyBy('id');
        $this->assertSame(0, $targets[$queued->id]['percent']);
        $this->assertSame('Menunggu', $targets[$queued->id]['status_label']);
        $this->assertSame(50, $targets[$running->id]['percent']);
        $this->assertSame('Nuclei', $targets[$running->id]['step']);
        $this->assertSame('bg-sky-600', $targets[$running->id]['bar_class']);
        $this->assertSame(100, $targets[$done->id]['percent']);

        $batch->targets()->update(['status' => ScanTargetStatus::Completed->value]);
        $this->assertTrue($this->getJson(route('scans.progress', $batch))->json('finished'));
    }

    public function test_halaman_antrean_menampilkan_loading_bar_setiap_website(): void
    {
        $batch = ScanBatch::factory()->create();
        ScanTarget::factory()->for($batch, 'batch')->create(['position' => 1, 'url' => 'https://satu.jemberkab.go.id', 'status' => ScanTargetStatus::Running]);
        ScanTarget::factory()->for($batch, 'batch')->create(['position' => 2, 'url' => 'https://dua.jemberkab.go.id']);

        $html = $this->get(route('scans.show', $batch))->assertOk()->getContent();

        $this->assertStringContainsString('data-progress-url="'.route('scans.progress', $batch).'"', $html);
        $this->assertSame(2, substr_count($html, 'data-target-progress='));
        $this->assertStringContainsString('0%', $html);
    }

    public function test_risk_register_web_sama_dengan_sheet_excel(): void
    {
        $this->fakeVulnerableSite();
        $target = $this->scan();
        $items = $target->batch->riskItems()->get();
        $this->assertNotEmpty($items);

        $page = $this->get(route('scans.risk-register', $target->batch))->assertOk();

        // Header mengikuti template sheet Perangkat Lunak
        $page->assertSeeInOrder([
            'REGISTER RISIKO KEAMANAN INFORMASI', '(ASET: PERANGKAT LUNAK)',
            'Risk No', 'Jenis Risiko', 'Identifikasi Resiko', 'Kontrol Saat Ini', 'Nilai Resiko Bawaan (Inherent Risk)',
            'EVALUASI RISIKO', 'RENCANA PENANGANAN RISIKO', 'Residual Risk', 'Rencana Kontrol Tambahan', 'Risk Owner',
            'Aset', 'Ancaman', 'Kerawanan/Kelemahan', 'Kategori', 'Dampak', 'Area Dampak',
            'Keputusan Penanganan Risiko', 'Prioritas Risiko', 'Opsi Penanganan', 'Rencana Aksi Penanganan Risiko', 'Keluaran',
            'Target/Jadwal Implementasi', 'Penanggung Jawab', 'Apakah Terdapat Residual Risk', 'Kemungkinan', 'RR', 'Status',
            'IR', 'Level Risiko',
        ]);

        // Setiap nilai yang ditulis ke Excel juga tampil di halaman, dengan urutan baris yang sama
        $base = tempnam(sys_get_temp_dir(), 'siprika-sheet');
        @unlink($base);
        (new RiskRegisterExporter)->export($items, $path = $base.'.xlsx');
        $sheet = IOFactory::load($path)->getSheetByName('Perangkat Lunak');

        foreach ($items->values() as $index => $item) {
            foreach (RiskRegisterSheet::values($item, $index + 1) as $column => $value) {
                $cell = $sheet->getCell($column.(7 + $index))->getValue();
                $cell = $cell instanceof RichText ? $cell->getPlainText() : $cell;

                $this->assertEquals($value === '' ? null : $value, $cell, "Kolom {$column} baris ".(7 + $index));
                $page->assertSee((string) $value);
            }
        }

        @unlink($path);

        $page->assertSee('PL-001')->assertSee('Mitigasi Risiko')->assertSee('Sangat Tinggi');
    }

    public function test_tab_risk_register_website_memakai_tampilan_sheet(): void
    {
        $this->fakeVulnerableSite();
        $target = $this->scan();

        $this->get(route('targets.show', ['scanTarget' => $target, 'tab' => 'risk']))
            ->assertOk()
            ->assertSee('Identifikasi Resiko')
            ->assertSee('RENCANA PENANGANAN RISIKO')
            ->assertSee(route('scans.risk-register', $target->batch));
    }

    public function test_format_durasi_dan_perkiraan_sisa(): void
    {
        $this->assertSame('0 detik', Duration::format(-5));
        $this->assertSame('45 detik', Duration::format(45));
        $this->assertSame('1 menit', Duration::format(60));
        $this->assertSame('22 menit 23 detik', Duration::format(1343));
        $this->assertSame('1 jam', Duration::format(3600));
        $this->assertSame('1 jam 5 menit', Duration::format(3930));

        $this->assertSame('< 1 menit', Duration::approximate(30));
        $this->assertSame('± 2 menit', Duration::approximate(61));
        $this->assertSame('± 19 menit', Duration::approximate(1131));
        $this->assertSame('± 1 jam 1 menit', Duration::approximate(3601));
    }

    public function test_perkiraan_sisa_waktu_memakai_bobot_tahap(): void
    {
        $now = 1_000_000.0;
        $steps = [
            ['status' => ScanProgress::DONE, 'weight' => 20],
            ['status' => ScanProgress::RUNNING, 'weight' => 1300, 'started_at' => $now - 300],
            ['status' => ScanProgress::WAITING, 'weight' => 60],
        ];

        // 1000 sisa Nuclei + 60 AI
        $this->assertSame(1060, ScanProgress::remainingSeconds($steps, $now));

        // Tahap yang lebih lama dari perkiraan tetap menyisakan 5% bobotnya
        $steps[1]['started_at'] = $now - 5000;
        $this->assertSame(125, ScanProgress::remainingSeconds($steps, $now));
    }

    public function test_waktu_mulai_lama_berjalan_dan_durasi_tampil_di_halaman(): void
    {
        $this->travelTo('2026-09-28 13:31:00');
        $batch = ScanBatch::create(['mode' => ScanMode::Standard]);
        $create = fn (int $position, array $attributes) => $batch->targets()->create(['position' => $position, 'url' => "https://web{$position}.jemberkab.go.id", 'host' => "web{$position}.jemberkab.go.id"] + $attributes);

        $finished = $create(1, ['status' => ScanTargetStatus::Completed, 'started_at' => '2026-09-28 13:19:51', 'finished_at' => '2026-09-28 13:42:14']);
        $running = $create(2, ['status' => ScanTargetStatus::Running, 'started_at' => '2026-09-28 13:19:51', 'progress' => [
            ['key' => 'nuclei', 'label' => 'Nuclei', 'status' => ScanProgress::RUNNING, 'weight' => 1300, 'started_at' => now()->subSeconds(669)->getTimestamp()],
        ]]);
        $overnight = $create(3, ['status' => ScanTargetStatus::Partial, 'started_at' => '2026-09-27 23:50:00', 'finished_at' => '2026-09-28 00:20:00']);
        $create(4, ['status' => ScanTargetStatus::Queued]);

        $this->get(route('scans.show', $batch))
            ->assertOk()
            ->assertSeeInOrder(['Mulai 28-09-2026 13:19:51', 'Selesai 13:42:14', 'Durasi', '22 menit 23 detik'])
            ->assertSeeInOrder(['Mulai 28-09-2026 13:19:51', 'Berjalan', '11 menit 9 detik', 'Perkiraan sisa', '± 11 menit'])
            ->assertSeeInOrder(['Mulai 27-09-2026 23:50:00', 'Selesai 28-09-2026 00:20:00', '30 menit'])
            ->assertSee('Menunggu antrean');

        // Hanya website yang sedang diperiksa yang lama berjalannya diperbarui tiap detik oleh JavaScript
        $page = $this->get(route('scans.show', $batch))->getContent();
        $this->assertMatchesRegularExpression('/data-scan-time="'.$running->id.'"\s+data-running/', $page);
        $this->assertDoesNotMatchRegularExpression('/data-scan-time="'.$finished->id.'"\s+data-running/', $page);

        $this->getJson(route('scans.progress', $batch))
            ->assertJsonPath('targets.0.elapsed', 1343)
            ->assertJsonPath('targets.0.remaining', null)
            ->assertJsonPath('targets.1.elapsed', 669)
            ->assertJsonPath('targets.1.remaining', 631)
            ->assertJsonPath('targets.3.elapsed', null);

        $this->get(route('targets.show', $finished))->assertOk()->assertSeeInOrder(['Mulai 28-09-2026 13:19:51', 'Selesai 13:42:14', '22 menit 23 detik']);
        $this->get(route('targets.show', $running))->assertOk()->assertSeeInOrder(['Berjalan', '11 menit 9 detik']);
        $this->get(route('targets.show', $overnight))->assertOk()->assertSee('Selesai 28-09-2026 00:20:00');
    }
}
