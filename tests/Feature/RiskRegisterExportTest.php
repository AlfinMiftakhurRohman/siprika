<?php

namespace Tests\Feature;

use App\Models\RiskRegisterItem;
use App\Risk\RiskEngine;
use App\Risk\RiskRegisterExporter;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Collection;
use PhpOffice\PhpSpreadsheet\IOFactory;
use PhpOffice\PhpSpreadsheet\RichText\RichText;
use PhpOffice\PhpSpreadsheet\Spreadsheet;
use PhpOffice\PhpSpreadsheet\Worksheet\Worksheet;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;
use ZipArchive;

class RiskRegisterExportTest extends TestCase
{
    use RefreshDatabase;

    private string $path;

    protected function setUp(): void
    {
        parent::setUp();

        $base = tempnam(sys_get_temp_dir(), 'siprika-test');
        @unlink($base);
        $this->path = $base.'.xlsx';
    }

    protected function tearDown(): void
    {
        @unlink($this->path);

        parent::tearDown();
    }

    /**
     * Tabel bagian 24.3: dampak, kemungkinan, IR, level, status.
     *
     * @return array<string, array{int, int, int, string, string}>
     */
    public static function blueprintProvider(): array
    {
        return [
            'no-https' => [3, 2, 11, 'Sedang', 'Not Acceptable'],
            'http-not-redirected' => [2, 2, 7, 'Rendah', 'Acceptable'],
            'missing-hsts' => [2, 2, 7, 'Rendah', 'Acceptable'],
            'missing-csp' => [2, 2, 7, 'Rendah', 'Acceptable'],
            'missing-x-frame-options' => [2, 2, 7, 'Rendah', 'Acceptable'],
            'missing-x-content-type-options' => [1, 2, 2, 'Sangat Rendah', 'Acceptable'],
            'missing-referrer-policy' => [1, 1, 1, 'Sangat Rendah', 'Acceptable'],
            'insecure-cookie' => [2, 2, 7, 'Rendah', 'Acceptable'],
            'tls-cert-invalid' => [3, 5, 18, 'Tinggi', 'Not Acceptable'],
            'tls-chain-incomplete' => [2, 3, 10, 'Rendah', 'Acceptable'],
            'tls-cert-expiring' => [3, 3, 14, 'Sedang', 'Not Acceptable'],
            'tls-legacy-protocol' => [2, 2, 7, 'Rendah', 'Acceptable'],
            'server-version-disclosure' => [1, 2, 2, 'Sangat Rendah', 'Acceptable'],
            'directory-listing' => [2, 5, 15, 'Sedang', 'Not Acceptable'],
            'exposed-sensitive-file' => [4, 5, 23, 'Sangat Tinggi', 'Not Acceptable'],
        ];
    }

    #[DataProvider('blueprintProvider')]
    public function test_katalog_dan_matriks_sesuai_blueprint(int $impact, int $likelihood, int $ir, string $level, string $status): void
    {
        $key = $this->dataName();
        $catalog = config("siprika_catalog.{$key}");

        $this->assertSame($impact, $catalog['impact']);
        $this->assertSame($likelihood, $catalog['likelihood']);
        $this->assertSame($ir, RiskEngine::riskValue($impact, $likelihood));
        $this->assertSame($level, RiskEngine::level($impact, $likelihood));
        $this->assertSame($status, RiskEngine::status($ir));
    }

    public function test_klasifikasi_katalog_memakai_nilai_dropdown_template(): void
    {
        $spreadsheet = IOFactory::load(config('siprika.excel.template'));
        $categories = array_filter(array_map('trim', array_column($spreadsheet->getSheetByName('List Kategori Risiko Keamanan')->rangeToArray('A2:A13'), 0)));
        $impactAreas = ['Finansial', 'Reputasi', 'Kinerja', 'Layanan Organisasi', 'Operasional dan Aset TIK', 'Hukum dan Regulasi', 'SDM'];

        foreach (config('siprika_catalog') as $key => $entry) {
            $this->assertContains($entry['category'], $categories, $key);
            $this->assertContains($entry['impact_area'], $impactAreas, $key);
        }

        $this->assertContains(config('siprika_risk.nuclei.category'), $categories);
    }

    /**
     * @return Collection<int, RiskRegisterItem>
     */
    private function items(int $count): Collection
    {
        return collect(range(1, $count))->map(fn (int $i) => new RiskRegisterItem([
            'residual_impact' => RiskEngine::residual($i % 2 ? 4 : 2)[0],
            'residual_likelihood' => RiskEngine::residual($i % 2 ? 4 : 2)[1],
            'residual_risk' => RiskEngine::riskValue(...RiskEngine::residual($i % 2 ? 4 : 2)),
            'residual_status' => RiskRegisterItem::ACCEPTABLE,
            'asset' => "Website Dinas {$i} (dinas{$i}.jemberkab.go.id)",
            'threat' => 'Terjadi peretasan pada aplikasi',
            'vulnerability' => 'Lemahnya mekanisme kriptografi aplikasi (header Strict-Transport-Security tidak ditemukan pada respons HTTPS)',
            'category' => 'Keamanan Infrastruktur',
            'impact_description' => 'Pengguna berpotensi mengakses layanan tanpa HTTPS & "enkripsi" <aman>.',
            'impact_area' => 'Operasional dan Aset TIK',
            'impact' => $i % 2 ? 4 : 2,
            'likelihood' => $i % 2 ? 5 : 2,
            'inherent_risk' => $i % 2 ? 23 : 7,
            'risk_level' => $i % 2 ? 'Sangat Tinggi' : 'Rendah',
            'risk_status' => $i % 2 ? RiskRegisterItem::NOT_ACCEPTABLE : RiskRegisterItem::ACCEPTABLE,
            'priority' => $i,
            'action_plan' => 'Tambahkan header HSTS.',
            'output' => 'Header HSTS aktif.',
            'additional_control' => 'Periksa konfigurasi secara berkala.',
            'text_source' => 'catalog',
        ]));
    }

    /**
     * @param  Collection<int, RiskRegisterItem>|null  $items
     */
    private function export(int $count, ?Collection $items = null): Spreadsheet
    {
        (new RiskRegisterExporter)->export($items ?? $this->items($count), $this->path);

        return IOFactory::load($this->path);
    }

    /**
     * Sel teks ditulis sebagai inline string yang dibaca PhpSpreadsheet sebagai RichText.
     */
    private function text(Worksheet $sheet, string $cell): mixed
    {
        $value = $sheet->getCell($cell)->getValue();

        return $value instanceof RichText ? $value->getPlainText() : $value;
    }

    public function test_export_mengisi_sheet_perangkat_lunak_mulai_baris_7_dan_rumus_terhitung(): void
    {
        $sheet = $this->export(7)->getSheetByName('Perangkat Lunak');

        $this->assertSame('PL-001', $this->text($sheet, 'A7'));
        $this->assertSame('Negatif', $this->text($sheet, 'B7'));
        $this->assertSame('Website Dinas 1 (dinas1.jemberkab.go.id)', $this->text($sheet, 'C7'));
        $this->assertSame('Signifikan', $this->text($sheet, 'J7'));
        $this->assertSame('Hampir Pasti Terjadi', $this->text($sheet, 'K7'));
        $this->assertSame('Belum teridentifikasi dari pemeriksaan eksternal', $this->text($sheet, 'I7'));
        $this->assertSame('Ya', $this->text($sheet, 'N7'));
        $this->assertSame(1, $this->text($sheet, 'O7'));
        $this->assertSame('Mitigasi Risiko', $this->text($sheet, 'P7'));
        $this->assertSame('Pengguna berpotensi mengakses layanan tanpa HTTPS & "enkripsi" <aman>.', $this->text($sheet, 'G7'));

        // Kolom yang diisi staf tetap kosong (bagian 17)
        foreach (['S', 'T', 'AA'] as $column) {
            $this->assertNull($this->text($sheet, "{$column}7"), $column);
        }

        // Keputusan dan opsi penanganan diisi untuk semua baris, termasuk yang Acceptable (bagian 25)
        $this->assertSame('Acceptable', $sheet->getCell('AF8')->getCalculatedValue());
        $this->assertSame('Ya', $this->text($sheet, 'N8'));
        $this->assertSame('Mitigasi Risiko', $this->text($sheet, 'P8'));

        // Residual (bagian 24.6): ada, dampak sama dengan inherent, kemungkinan Hampir Tidak Terjadi
        $this->assertSame('Ya', $this->text($sheet, 'U7'));
        $this->assertSame('Signifikan', $this->text($sheet, 'V7'));
        $this->assertSame('Hampir Tidak Terjadi', $this->text($sheet, 'W7'));
        $this->assertSame('Kurang Signifikan', $this->text($sheet, 'V8'));
        $this->assertSame('Hampir Tidak Terjadi', $this->text($sheet, 'W8'));

        // Rumus template disalin dan dihitung dari matriks sheet Peta Risiko
        $this->assertSame('=INDEX(RiskMatrix,MATCH(K13,RangeKemungkinan,0),MATCH(J13,RangeDampak,0))', $this->text($sheet, 'L13'));
        $this->assertEquals(23, $sheet->getCell('L7')->getCalculatedValue());
        $this->assertSame('Sangat Tinggi', $sheet->getCell('M7')->getCalculatedValue());
        $this->assertEquals(7, $sheet->getCell('L8')->getCalculatedValue());
        $this->assertSame('Not Acceptable', $sheet->getCell('AF7')->getCalculatedValue());
        $this->assertSame('PL-007', $this->text($sheet, 'A13'));

        // RR dan status residual dihitung rumus template, tidak ditulis nilainya
        $this->assertSame('=IF(U13="Ya",(INDEX(RiskMatrix,MATCH(W13,RangeKemungkinan,0),MATCH(V13,RangeDampak,0))),"N/A")', $this->text($sheet, 'X13'));
        $this->assertSame('=IF(ISNUMBER(X13),IF(X13>=11,"Not Acceptable","Acceptable"),"N/A")', $this->text($sheet, 'Y13'));
        $this->assertEquals(8, $sheet->getCell('X7')->getCalculatedValue());
        $this->assertSame('Acceptable', $sheet->getCell('Y7')->getCalculatedValue());
        $this->assertEquals(3, $sheet->getCell('X8')->getCalculatedValue());
        $this->assertEquals(7, $sheet->getCell('AB14')->getCalculatedValue());
        $this->assertEquals(0, $sheet->getCell('AC14')->getCalculatedValue());

        // Baris total pindah ke bawah data dan SUM diperluas
        $this->assertSame('=SUM(AG7:AG13)', $this->text($sheet, 'AG14'));
        $this->assertSame('=SUM(AG14:AH14)', $this->text($sheet, 'AI14'));
        $this->assertEquals(7, $sheet->getCell('AI14')->getCalculatedValue());
        $this->assertEquals(4, $sheet->getCell('AH14')->getCalculatedValue());
    }

    public function test_dropdown_diperluas_ke_semua_baris_baru(): void
    {
        $sheet = $this->export(7)->getSheetByName('Perangkat Lunak');
        $ranges = array_keys($sheet->getDataValidationCollection());

        foreach (['K7:K13 W7:W13', 'J7:J13 V7:V13', 'H7:H13', 'P7:P13', 'N7:N13 U7:U13', 'B7:B13', 'F1 F3:F1048576'] as $range) {
            $this->assertContains($range, $ranges);
        }
    }

    public function test_sheet_ringkasan_mengacu_ke_baris_total_baru(): void
    {
        $summary = $this->export(7)->getSheetByName('Ringkasan');

        $this->assertSame("='Perangkat Lunak'!AI14", $summary->getCell('B11')->getValue());
        $this->assertEquals(7, $summary->getCell('B11')->getCalculatedValue());
        $this->assertSame("='Perangkat Lunak'!AB14", $summary->getCell('F11')->getValue());
        // Sheet aset lain tidak berubah
        $this->assertSame("='Data dan Informasi'!AI12", $summary->getCell('B10')->getValue());
    }

    public function test_ringkasan_menghitung_inherent_dan_residual_sesuai_sheet_perangkat_lunak(): void
    {
        $summary = $this->export(7)->getSheetByName('Ringkasan');

        // Inherent: 3 Acceptable (IR 7) dan 4 Not Acceptable (IR 23)
        $this->assertEquals(3, $summary->getCell('C11')->getCalculatedValue());
        $this->assertEquals(4, $summary->getCell('D11')->getCalculatedValue());
        // Residual: semua Acceptable karena kemungkinan turun ke Hampir Tidak Terjadi
        $this->assertEquals(7, $summary->getCell('F11')->getCalculatedValue());
        $this->assertEquals(0, $summary->getCell('G11')->getCalculatedValue());

        // Persentase Acceptable dibagi jumlah risiko; rumus template E11 keliru membagi dengan jumlah Unacceptable
        $this->assertSame('=IFERROR(C11/B11,0)', $summary->getCell('E11')->getValue());
        $this->assertEqualsWithDelta(3 / 7, $summary->getCell('E11')->getCalculatedValue(), 0.0001);
        $this->assertSame('=IFERROR(F11/B11,0)', $summary->getCell('H11')->getValue());
        $this->assertEquals(1, $summary->getCell('H11')->getCalculatedValue());
    }

    public function test_ringkasan_tanpa_risiko_tidak_menghasilkan_pembagian_nol(): void
    {
        $summary = $this->export(0, collect())->getSheetByName('Ringkasan');

        $this->assertEquals(0, $summary->getCell('B11')->getCalculatedValue());
        $this->assertEquals(0, $summary->getCell('E11')->getCalculatedValue());
        $this->assertEquals(0, $summary->getCell('H11')->getCalculatedValue());
    }

    public function test_rumus_persentase_semua_baris_aset_ringkasan_diperbaiki_tanpa_merusak_rumus_shared(): void
    {
        (new RiskRegisterExporter)->export($this->items(3), $this->path);

        $zip = new ZipArchive;
        $zip->open($this->path);
        $xml = $zip->getFromName('xl/worksheets/sheet1.xml');
        $zip->close();

        // Pada template, E11 adalah induk rumus shared E11:E14 dan H10 induk rumus shared H10:H14
        $this->assertDoesNotMatchRegularExpression('/<f t="shared"[^>]*si="[01]"/', $xml);

        $summary = IOFactory::load($this->path)->getSheetByName('Ringkasan');

        // Template membagi dengan jumlah Unacceptable (C/D) pada E11 sampai E14
        foreach (range(10, 14) as $row) {
            $this->assertSame("=IFERROR(C{$row}/B{$row},0)", $summary->getCell("E{$row}")->getValue(), "E{$row}");
            $this->assertSame("=IFERROR(F{$row}/B{$row},0)", $summary->getCell("H{$row}")->getValue(), "H{$row}");
        }

        // Nilai contoh bawaan sheet aset lain: 1 Acceptable dari 2 risiko
        $this->assertEquals(0.5, $summary->getCell('E12')->getCalculatedValue());
        $this->assertEquals(0.5, $summary->getCell('H12')->getCalculatedValue());
    }

    public function test_baris_ringkasan_yang_merujuk_sheet_lain_dari_labelnya_diarahkan_ke_sheet_yang_benar(): void
    {
        $summary = $this->export(3)->getSheetByName('Ringkasan');

        // Template: baris "SDM & Pihak Ketiga" mengambil total sheet 'Sarana Pendukung'
        $this->assertSame("='SDM & Pihak Ketiga'!AI12", $summary->getCell('B14')->getValue());
        $this->assertSame("='SDM & Pihak Ketiga'!AC12", $summary->getCell('G14')->getValue());
        // Baris lain yang sudah benar tidak berubah
        $this->assertSame("='Sarana Pendukung'!AI12", $summary->getCell('B13')->getValue());
        $this->assertSame("='Perangkat Keras'!AG12", $summary->getCell('C12')->getValue());
    }

    public function test_data_sedikit_tetap_menyisakan_baris_template_dan_contoh_dihapus(): void
    {
        $sheet = $this->export(2)->getSheetByName('Perangkat Lunak');

        $this->assertSame('PL-002', $this->text($sheet, 'A8'));
        // Baris contoh bawaan template (PL-003 dst dan isi contoh) dihapus
        $this->assertNull($this->text($sheet, 'A9'));
        $this->assertNull($this->text($sheet, 'C9'));
        $this->assertSame('=INDEX(RiskMatrix,MATCH(K11,RangeKemungkinan,0),MATCH(J11,RangeDampak,0))', $this->text($sheet, 'L11'));
        $this->assertSame('=SUM(AB7:AB11)', $this->text($sheet, 'AB12'));
    }

    public function test_bagian_lain_file_template_tidak_berubah(): void
    {
        (new RiskRegisterExporter)->export($this->items(8), $this->path);

        $template = new ZipArchive;
        $template->open(config('siprika.excel.template'));
        $result = new ZipArchive;
        $result->open($this->path);

        $unchanged = [
            'xl/worksheets/sheet2.xml', 'xl/worksheets/sheet4.xml', 'xl/worksheets/sheet7.xml', 'xl/worksheets/sheet8.xml',
            'xl/styles.xml', 'xl/sharedStrings.xml', 'xl/externalLinks/externalLink1.xml',
            'xl/threadedComments/threadedComment2.xml', 'xl/drawings/drawing3.xml', 'xl/media/image1.png',
        ];

        foreach ($unchanged as $file) {
            $this->assertSame($template->getFromName($file), $result->getFromName($file), $file);
        }

        // calcChain dihapus dan Excel diminta menghitung ulang saat dibuka
        $this->assertFalse($result->locateName('xl/calcChain.xml'));
        $this->assertStringNotContainsString('calcChain', $result->getFromName('[Content_Types].xml'));
        $this->assertStringContainsString('fullCalcOnLoad="1"', $result->getFromName('xl/workbook.xml'));
        $this->assertStringContainsString("'Perangkat Lunak'!\$A\$1:\$AA\$14", $result->getFromName('xl/workbook.xml'));

        $template->close();
        $result->close();
    }
}
