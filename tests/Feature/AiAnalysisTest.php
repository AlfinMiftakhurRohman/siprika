<?php

namespace Tests\Feature;

use App\Ai\AiOutputValidator;
use App\Enums\ObservationStatus;
use App\Enums\ScanTargetStatus;
use App\Models\AiAnalysis;
use GuzzleHttp\Promise\PromiseInterface;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Tests\Support\FakeNetwork;
use Tests\Support\InteractsWithScanner;
use Tests\TestCase;

class AiAnalysisTest extends TestCase
{
    use InteractsWithScanner;
    use RefreshDatabase;

    private const HOME = 'https://web.jemberkab.go.id/';

    private const AI_URL = 'http://127.0.0.1:8081/v1/chat/completions';

    protected function setUp(): void
    {
        parent::setUp();

        $this->setUpScanner();
        config(['siprika.ai.enabled' => true, 'siprika.ai.url' => 'http://127.0.0.1:8081']);
    }

    /**
     * Website dengan satu masalah saja: HSTS tidak ada.
     *
     * @param  mixed  $aiResponse
     */
    private function fakeSite($aiResponse): void
    {
        $headers = self::secureHeaders();
        unset($headers['Strict-Transport-Security']);

        FakeNetwork::http([
            self::HOME => Http::response('<title>Web</title>', 200, $headers),
            'http://web.jemberkab.go.id/' => Http::response('', 301, ['Location' => self::HOME]),
            self::AI_URL => $aiResponse,
        ]);
    }

    /**
     * @param  array<string, string>  $overrides
     */
    private static function aiReply(array $overrides = []): PromiseInterface
    {
        $content = $overrides + [
            'finding' => 'HSTS belum diterapkan',
            'threat' => 'Penyadapan komunikasi',
            'vulnerability' => 'Website tidak memaksa browser memakai HTTPS',
            'category' => 'Keamanan Infrastruktur',
            'impact_description' => 'Dampak versi AI: pengguna dapat diarahkan ke koneksi tanpa enkripsi.',
            'recommendation' => 'Rencana aksi versi AI: aktifkan HSTS dengan max-age minimal satu tahun.',
            'additional_control' => 'Kontrol versi AI: tinjau konfigurasi header secara berkala.',
        ];

        return Http::response(['choices' => [['message' => ['content' => json_encode($content)]]]]);
    }

    public function test_teks_ai_dipakai_di_risk_register_dan_disimpan_per_kunci_finding(): void
    {
        $this->fakeSite(self::aiReply());

        $target = $this->scan();

        $item = $target->riskItems->firstWhere('finding_key', 'missing-hsts');
        $this->assertSame('ai', $item->text_source);
        $this->assertStringStartsWith('Dampak versi AI', $item->impact_description);
        $this->assertStringStartsWith('Rencana aksi versi AI', $item->action_plan);
        $this->assertStringStartsWith('Kontrol versi AI', $item->additional_control);
        // Kategori dan ancaman tetap dari katalog supaya sesuai dropdown template
        $this->assertSame('Keamanan Infrastruktur', $item->category);
        $this->assertSame('Terjadi peretasan pada aplikasi', $item->threat);

        $this->assertSame(1, AiAnalysis::count());

        // AI tidak menerima URL atau output mentah scanner
        Http::assertSent(function (Request $request) {
            if ($request->url() !== self::AI_URL) {
                return false;
            }

            $input = $request->data()['messages'][1]['content'];

            // Hasil AI dipakai ulang untuk website lain, jadi evidence website ini tidak ikut dikirim
            return str_contains($input, 'missing-hsts')
                && ! str_contains($input, 'https://')
                && ! str_contains($input, 'tidak ditemukan pada respons HTTPS');
        });

        // Website lain dengan finding yang sama memakai hasil tersimpan tanpa memanggil AI lagi
        $calls = count(Http::recorded(fn (Request $request) => $request->url() === self::AI_URL));
        $second = $this->scan('https://web.jemberkab.go.id', $target->batch);

        $this->assertSame('ai', $second->riskItems->firstWhere('finding_key', 'missing-hsts')->text_source);
        $this->assertSame($calls, count(Http::recorded(fn (Request $request) => $request->url() === self::AI_URL)));
    }

    public function test_hasil_ai_tersimpan_tidak_dipakai_saat_ai_dinonaktifkan(): void
    {
        $this->fakeSite(self::aiReply());
        $this->scan();
        $this->assertSame(1, AiAnalysis::count());

        config(['siprika.ai.enabled' => false]);
        $target = $this->scan();

        $item = $target->riskItems->firstWhere('finding_key', 'missing-hsts');
        $this->assertSame('catalog', $item->text_source);
        $this->assertSame(config('siprika_catalog.missing-hsts.recommendation'), $item->action_plan);
    }

    public function test_ai_mati_tidak_menggagalkan_scan_dan_memakai_teks_katalog(): void
    {
        $this->fakeSite('timeout');

        $target = $this->scan();

        $this->assertSame(ScanTargetStatus::Completed, $target->status);
        $this->assertSame(ObservationStatus::Error, $target->observations->firstWhere('check_key', 'ai-analysis')->status);

        $item = $target->riskItems->firstWhere('finding_key', 'missing-hsts');
        $this->assertSame('catalog', $item->text_source);
        $this->assertSame(config('siprika_catalog.missing-hsts.recommendation'), $item->action_plan);
    }

    public function test_output_ai_yang_mengarang_cve_ditolak(): void
    {
        $this->fakeSite(self::aiReply(['recommendation' => 'Segera tambal CVE-2021-44228 pada server.']));

        $target = $this->scan();

        $this->assertSame(0, AiAnalysis::count());
        $this->assertSame('catalog', $target->riskItems->firstWhere('finding_key', 'missing-hsts')->text_source);
        $this->assertStringContainsString('ditolak validasi', $target->observations->firstWhere('check_key', 'ai-analysis')->summary);
    }

    public function test_output_ai_bukan_json_ditolak(): void
    {
        $this->fakeSite(Http::response(['choices' => [['message' => ['content' => 'Maaf, saya tidak bisa.']]]]));

        $target = $this->scan();

        $this->assertSame(0, AiAnalysis::count());
        $this->assertSame(ScanTargetStatus::Completed, $target->status);
    }

    public function test_validator_output_ai(): void
    {
        $validator = new AiOutputValidator;
        $input = ['finding_key' => 'nuclei:x', 'title' => 'Apache 2.4.49 Path Traversal', 'cve' => 'CVE-2021-41773'];
        $valid = array_fill_keys(AiOutputValidator::KEYS, 'Teks analisis.');

        $this->assertNull($validator->reject($valid, $input));
        $this->assertNull($validator->reject(['recommendation' => 'Perbarui Apache 2.4.49 dan tangani CVE-2021-41773, gunakan TLS 1.2.'] + $valid, $input));

        $this->assertStringContainsString('CVE-2022-0001', $validator->reject(['threat' => 'Terkait CVE-2022-0001.'] + $valid, $input));
        $this->assertStringContainsString('URL', $validator->reject(['recommendation' => 'Lihat https://contoh.com/patch.'] + $valid, $input));
        $this->assertStringContainsString('2.4.51', $validator->reject(['recommendation' => 'Perbarui ke versi 2.4.51.'] + $valid, $input));
        $this->assertStringContainsString('category', $validator->reject(['category' => ''] + $valid, $input));
    }
}
