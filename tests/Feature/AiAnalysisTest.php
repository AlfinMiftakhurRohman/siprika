<?php

namespace Tests\Feature;

use App\Ai\AiOutputValidator;
use App\Ai\SiteEvidence;
use App\Enums\ObservationStatus;
use App\Enums\ScanTargetStatus;
use App\Models\AiAnalysis;
use App\Risk\RiskEngine;
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
            // dan model diminta menulis teks umum
            return str_contains($request->data()['messages'][0]['content'], 'dipakai ulang untuk website lain')
                && str_contains($input, 'missing-hsts')
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
        // CVE dan versi yang merupakan informasi jenis finding (sama untuk semua website) boleh disebut
        $this->assertNull($validator->reject(['recommendation' => 'Perbarui Apache 2.4.49 dan tangani CVE-2021-41773, gunakan TLS 1.2.'] + $valid, $input));

        $this->assertStringContainsString('CVE-2022-0001', $validator->reject(['threat' => 'Terkait CVE-2022-0001.'] + $valid, $input));
        $this->assertStringContainsString('URL', $validator->reject(['recommendation' => 'Lihat https://contoh.com/patch.'] + $valid, $input));
        $this->assertStringContainsString('2.4.51', $validator->reject(['recommendation' => 'Perbarui ke versi 2.4.51.'] + $valid, $input));
        $this->assertStringContainsString('category', $validator->reject(['category' => ''] + $valid, $input));
    }

    public function test_validator_memeriksa_cve_versi_dan_url_terhadap_evidence_website_yang_diproses(): void
    {
        $validator = new AiOutputValidator;
        $input = ['finding_key' => 'server-version-disclosure', 'title' => 'Versi software server terlihat'];
        $valid = array_fill_keys(AiOutputValidator::KEYS, 'Sembunyikan nomor versi pada header Server.');
        $evidence = new SiteEvidence(
            'versi software terlihat pada header server: apache/2.4.41 (ubuntu) https://web.jemberkab.go.id/',
            ['https://web.jemberkab.go.id/', 'web.jemberkab.go.id'],
        );

        $this->assertNull($validator->reject($valid, $input, $evidence));

        // Tidak ada di evidence website ini: jawaban mengarang (bagian 27 poin 2)
        $this->assertStringContainsString('tidak ada di evidence website yang sedang diproses', $validator->reject(['recommendation' => 'Perbarui ke Apache 2.4.62.'] + $valid, $input, $evidence));
        $this->assertStringContainsString('tidak ada di evidence website yang sedang diproses', $validator->reject(['recommendation' => 'Tangani CVE-2021-41773.'] + $valid, $input, $evidence));

        // Ada di evidence tetapi khusus website ini, padahal teks dipakai ulang (bagian 27 poin 3)
        $this->assertStringContainsString('detail khusus website', $validator->reject(['finding' => 'Server menampilkan Apache 2.4.41.'] + $valid, $input, $evidence));
        $this->assertStringContainsString('detail khusus website', $validator->reject(['recommendation' => 'Ubah konfigurasi https://web.jemberkab.go.id/.'] + $valid, $input, $evidence));
        $this->assertStringContainsString('detail khusus website', $validator->reject(['recommendation' => 'Ubah konfigurasi web.jemberkab.go.id.'] + $valid, $input, $evidence));
    }

    public function test_detail_website_dicocokkan_sebagai_kata_utuh(): void
    {
        $validator = new AiOutputValidator;
        $input = ['finding_key' => 'insecure-cookie', 'title' => 'Atribut keamanan cookie tidak lengkap'];
        $valid = array_fill_keys(AiOutputValidator::KEYS, 'Pertimbangkan risiko residual setelah atribut cookie diperbaiki.');
        $evidence = new SiteEvidence('cookie sid tanpa secure; file .env', ['sid', '.env']);

        // "sid" di dalam kata "residual" bukan nama cookie website ini
        $this->assertNull($validator->reject($valid, $input, $evidence));
        $this->assertNull($validator->reject(['recommendation' => 'Periksa file .environment bawaan framework.'] + $valid, $input, $evidence));

        $this->assertStringContainsString('(sid)', $validator->reject(['recommendation' => 'Tambahkan Secure pada cookie SID.'] + $valid, $input, $evidence));
        $this->assertStringContainsString('(.env)', $validator->reject(['recommendation' => 'Hapus file .env dari web root.'] + $valid, $input, $evidence));
    }

    public function test_detail_website_dari_evidence_berisi_host_path_file_dan_cookie(): void
    {
        FakeNetwork::http([
            self::HOME => Http::response('<title>Web</title>', 200, ['Set-Cookie' => 'PHPSESSID=abc; path=/', 'Server' => 'Apache/2.4.41']),
            'http://web.jemberkab.go.id/' => Http::response('', 301, ['Location' => self::HOME]),
            'https://web.jemberkab.go.id/.env' => Http::response("APP_KEY=base64:rahasia\nDB_PASSWORD=rahasia\n", 200),
            self::AI_URL => 'timeout',
        ]);

        $target = $this->scan();
        $details = fn (string $key) => SiteEvidence::from($target->findings()->with('evidences')->firstWhere('finding_key', $key), $target)->details;

        $this->assertContains('web.jemberkab.go.id', $details('insecure-cookie'));
        $this->assertContains('PHPSESSID', $details('insecure-cookie'));
        $this->assertContains('/.env', $details('exposed-sensitive-file'));
        $this->assertContains('.env', $details('exposed-sensitive-file'));
        $this->assertStringContainsString('apache/2.4.41', SiteEvidence::from($target->findings()->with('evidences')->firstWhere('finding_key', 'server-version-disclosure'), $target)->text);
        // Nilai rahasia tidak pernah menjadi bagian evidence
        $this->assertStringNotContainsString('rahasia', SiteEvidence::from($target->findings()->with('evidences')->firstWhere('finding_key', 'exposed-sensitive-file'), $target)->text);
    }

    public function test_jawaban_ai_yang_memuat_nama_cookie_website_ditolak_dan_tidak_disimpan(): void
    {
        FakeNetwork::http([
            self::HOME => Http::response('<title>Web</title>', 200, ['Set-Cookie' => 'PHPSESSID=abc; path=/'] + self::secureHeaders()),
            'http://web.jemberkab.go.id/' => Http::response('', 301, ['Location' => self::HOME]),
            self::AI_URL => self::aiReply(['recommendation' => 'Tambahkan atribut Secure, HttpOnly, dan SameSite pada cookie PHPSESSID.']),
        ]);

        $target = $this->scan();

        $this->assertNull(AiAnalysis::firstWhere('finding_key', 'insecure-cookie'));
        $this->assertSame('catalog', $target->riskItems->firstWhere('finding_key', 'insecure-cookie')->text_source);
        $this->assertStringContainsString('PHPSESSID', $target->observations->firstWhere('check_key', 'ai-analysis')->raw['rejected']['insecure-cookie']);
    }

    public function test_hasil_ai_tersimpan_yang_memuat_detail_website_dihapus_dan_dianalisis_ulang(): void
    {
        // Hasil lama dari versi sebelumnya yang menyebut versi software website tertentu
        AiAnalysis::create([
            'finding_key' => 'server-version-disclosure',
            'recommendation' => 'Sembunyikan versi Apache 2.4.41 pada header Server.',
            'model' => 'lama',
        ] + array_fill_keys(AiOutputValidator::KEYS, 'Teks umum.'));

        FakeNetwork::http([
            self::HOME => Http::response('<title>Web</title>', 200, ['Server' => 'Apache/2.4.41'] + self::secureHeaders()),
            'http://web.jemberkab.go.id/' => Http::response('', 301, ['Location' => self::HOME]),
            self::AI_URL => self::aiReply(['recommendation' => 'Rencana aksi versi AI: sembunyikan nomor versi pada header Server.']),
        ]);

        $target = $this->scan();

        $analysis = AiAnalysis::firstWhere('finding_key', 'server-version-disclosure');
        $this->assertStringStartsWith('Rencana aksi versi AI', $analysis->recommendation);
        $this->assertArrayHasKey('server-version-disclosure', $target->observations->firstWhere('check_key', 'ai-analysis')->raw['purged']);
        $this->assertSame('ai', $target->riskItems->firstWhere('finding_key', 'server-version-disclosure')->text_source);
    }

    public function test_risk_engine_memvalidasi_hasil_ai_tersimpan_terhadap_website_yang_dinilai(): void
    {
        $this->fakeSite('timeout');
        $target = $this->scan();

        // Hasil tersimpan menyebut host website ini: tidak dipakai, kembali ke teks katalog
        AiAnalysis::query()->delete();
        AiAnalysis::create([
            'finding_key' => 'missing-hsts',
            'recommendation' => 'Aktifkan HSTS pada web.jemberkab.go.id.',
            'model' => 'lama',
        ] + array_fill_keys(AiOutputValidator::KEYS, 'Teks umum.'));
        app(RiskEngine::class)->assess($target);
        $this->assertSame('catalog', $target->riskItems()->firstWhere('finding_key', 'missing-hsts')->text_source);

        // Hasil tersimpan yang umum tetap dipakai
        AiAnalysis::query()->update(['recommendation' => 'Aktifkan HSTS dengan max-age minimal satu tahun.']);
        app(RiskEngine::class)->assess($target);
        $this->assertSame('ai', $target->riskItems()->firstWhere('finding_key', 'missing-hsts')->text_source);
    }

    public function test_siprika_recalculate_menghapus_hasil_ai_tersimpan_yang_tidak_lolos_validasi(): void
    {
        $this->fakeSite('timeout');
        $target = $this->scan();

        AiAnalysis::create([
            'finding_key' => 'missing-hsts',
            'recommendation' => 'Lihat panduan di https://contoh.com/hsts.',
            'model' => 'lama',
        ] + array_fill_keys(AiOutputValidator::KEYS, 'Teks umum.'));

        $this->artisan('siprika:recalculate', ['batch' => $target->scan_batch_id])
            ->expectsOutputToContain('Hasil AI missing-hsts dihapus')
            ->assertSuccessful();

        $this->assertSame(0, AiAnalysis::count());
        $this->assertSame('catalog', $target->riskItems()->firstWhere('finding_key', 'missing-hsts')->text_source);
    }
}
