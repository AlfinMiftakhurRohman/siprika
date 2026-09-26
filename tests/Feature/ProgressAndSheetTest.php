<?php

namespace Tests\Feature;

use App\Enums\ScanMode;
use App\Enums\ScanTargetStatus;
use App\Models\ScanBatch;
use App\Models\ScanTarget;
use App\Risk\RiskRegisterExporter;
use App\Risk\RiskRegisterSheet;
use App\Scanner\ScanProgress;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;
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

    public function test_persentase_progress_memakai_bobot_perkiraan_lama_tahap(): void
    {
        $now = 1_000_000.0;
        $steps = [
            ['status' => ScanProgress::DONE, 'weight' => 10],
            ['status' => ScanProgress::RUNNING, 'weight' => 100, 'started_at' => $now - 50],
            ['status' => ScanProgress::WAITING, 'weight' => 90],
        ];

        // 10 selesai + 50 dari tahap berjalan = 60 dari 200
        $this->assertSame(30, ScanProgress::percent($steps, $now));

        // Tahap yang lebih lama dari perkiraan berhenti di 95% bobotnya, tidak pernah melewati tahap berikutnya
        $steps[1]['started_at'] = $now - 10_000;
        $this->assertSame(52, ScanProgress::percent($steps, $now));

        // Semua tahap selesai tetap 99 sampai target benar-benar ditandai selesai
        $this->assertSame(99, ScanProgress::percent(array_map(fn ($s) => ['status' => ScanProgress::DONE] + $s, $steps), $now));
        $this->assertSame(0, ScanProgress::percent([], $now));
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
                ['key' => 'http-info', 'label' => 'Informasi HTTP', 'status' => ScanProgress::DONE, 'weight' => 50, 'started_at' => null],
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
}
