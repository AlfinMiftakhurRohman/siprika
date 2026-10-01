<?php

namespace Tests\Feature;

use App\Enums\ObservationStatus;
use App\Enums\ScanMode;
use App\Enums\ScanTargetStatus;
use App\Models\RiskRegisterItem;
use App\Models\ScanObservation;
use App\Models\ScanTarget;
use App\Scanner\Fingerprint;
use App\Scanner\Network\HttpExchange;
use App\Scanner\Network\HttpFailure;
use App\Scanner\Network\SafeHttpClient;
use App\Scanner\Parsers\NucleiParser;
use Carbon\CarbonImmutable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Process\PendingProcess;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Process;
use PHPUnit\Framework\Attributes\DataProvider;
use RuntimeException;
use Tests\Support\FakeNetwork;
use Tests\Support\InteractsWithScanner;
use Tests\TestCase;

class ScanPipelineTest extends TestCase
{
    use InteractsWithScanner;
    use RefreshDatabase;

    private const HOME = 'https://web.jemberkab.go.id/';

    protected function setUp(): void
    {
        parent::setUp();

        $this->setUpScanner();
    }

    /**
     * Website dengan banyak masalah konfigurasi.
     */
    private function fakeVulnerableSite(): void
    {
        $body = '<html><head><title>Dinas Contoh</title><meta name="generator" content="WordPress 6.4.2"></head>'
            .'<body><script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script></body></html>';

        FakeNetwork::http([
            self::HOME => Http::response($body, 200, [
                'Server' => 'Apache/2.4.41 (Ubuntu)',
                'X-Powered-By' => 'PHP/8.1.2',
                'Set-Cookie' => 'PHPSESSID=abc123; path=/',
            ]),
            'http://web.jemberkab.go.id/' => Http::response($body, 200),
            'https://web.jemberkab.go.id/.env' => Http::response("APP_NAME=Contoh\nAPP_KEY=base64:rahasiasekali\nDB_PASSWORD=sangatrahasia\n", 200),
            'https://web.jemberkab.go.id/uploads/' => Http::response('<html><head><title>Index of /uploads</title></head><body></body></html>', 200),
        ]);

        $this->network->protocols['TLSv1.0'] = 'accepted';
    }

    private function observation(ScanTarget $target, string $key): ?ScanObservation
    {
        return $target->observations->firstWhere('check_key', $key);
    }

    public function test_website_bermasalah_menghasilkan_finding_dan_risk_register_sesuai_aturan(): void
    {
        $this->fakeVulnerableSite();

        $target = $this->scan();

        $this->assertSame(ScanTargetStatus::Completed, $target->status);
        $this->assertNotNull($target->finished_at);

        $expected = [
            // kunci => [IR, level, status] sesuai tabel bagian 24.3
            'exposed-sensitive-file' => [23, 'Sangat Tinggi', 'Not Acceptable'],
            'directory-listing' => [15, 'Sedang', 'Not Acceptable'],
            'http-not-redirected' => [7, 'Rendah', 'Acceptable'],
            'missing-hsts' => [7, 'Rendah', 'Acceptable'],
            'missing-csp' => [7, 'Rendah', 'Acceptable'],
            'missing-x-frame-options' => [7, 'Rendah', 'Acceptable'],
            'insecure-cookie' => [7, 'Rendah', 'Acceptable'],
            'tls-legacy-protocol' => [7, 'Rendah', 'Acceptable'],
            'missing-x-content-type-options' => [2, 'Sangat Rendah', 'Acceptable'],
            'server-version-disclosure' => [2, 'Sangat Rendah', 'Acceptable'],
            'missing-referrer-policy' => [1, 'Sangat Rendah', 'Acceptable'],
        ];

        $this->assertEqualsCanonicalizing(array_keys($expected), $target->findings->pluck('finding_key')->all());

        $items = $target->riskItems->keyBy('finding_key');

        foreach ($expected as $key => [$ir, $level, $status]) {
            $this->assertSame($ir, $items[$key]->inherent_risk, $key);
            $this->assertSame($level, $items[$key]->risk_level, $key);
            $this->assertSame($status, $items[$key]->risk_status, $key);
        }

        // Prioritas 1 adalah IR tertinggi
        $this->assertSame('exposed-sensitive-file', $target->riskItems->firstWhere('priority', 1)->finding_key);
        $this->assertSame('directory-listing', $target->riskItems->firstWhere('priority', 2)->finding_key);

        $hsts = $items['missing-hsts'];
        $this->assertSame('Website Dinas Contoh (web.jemberkab.go.id)', $hsts->asset);
        $this->assertSame('Terjadi peretasan pada aplikasi', $hsts->threat);
        $this->assertSame('Keamanan Infrastruktur', $hsts->category);
        $this->assertSame('Lemahnya mekanisme kriptografi aplikasi (header Strict-Transport-Security tidak ditemukan pada respons HTTPS)', $hsts->vulnerability);
        $this->assertSame('catalog', $hsts->text_source);

        // Evidence file sensitif disamarkan
        $snippet = $target->findings->firstWhere('finding_key', 'exposed-sensitive-file')->evidences->first()->raw['snippet'];
        $this->assertStringContainsString('APP_KEY=***', $snippet);
        $this->assertStringNotContainsString('rahasia', $snippet);

        // Cookie sesi tanpa Secure, HttpOnly, dan SameSite
        $cookie = $target->findings->firstWhere('finding_key', 'insecure-cookie')->evidences->first()->detail;
        $this->assertSame('cookie PHPSESSID tanpa Secure, tanpa HttpOnly, tanpa SameSite', $cookie);

        $this->assertSame('Dinas Contoh', $target->overview['title']);
        $this->assertSame('WordPress 6.4.2', $target->overview['cms']);
        $this->assertContains('jQuery', array_column($target->overview['technologies'], 'name'));
        $this->assertSame('3.7.1', collect($target->overview['technologies'])->firstWhere('name', 'jQuery')['version']);

        // Tool eksternal yang belum dipasang dicatat NOT ASSESSED, bukan PASS
        foreach (['nuclei', 'testssl', 'whatweb', 'zap-passive', 'service-version'] as $key) {
            $this->assertSame(ObservationStatus::NotAssessed, $this->observation($target, $key)->status, $key);
        }
    }

    public function test_website_yang_aman_tidak_menghasilkan_finding(): void
    {
        FakeNetwork::http([
            self::HOME => Http::response('<html><head><title>Aman</title></head></html>', 200, self::secureHeaders()),
            'http://web.jemberkab.go.id/' => Http::response('', 301, ['Location' => self::HOME]),
        ]);

        $target = $this->scan();

        $this->assertSame(ScanTargetStatus::Completed, $target->status);
        $this->assertCount(0, $target->findings);
        $this->assertCount(0, $target->riskItems);
        $this->assertSame(ObservationStatus::Pass, $this->observation($target, 'http-redirect')->status);
        $this->assertSame(ObservationStatus::Pass, $this->observation($target, 'cookie-security')->status);
        $this->assertSame(ObservationStatus::Pass, $this->observation($target, 'tls-certificate')->status);
    }

    public function test_domain_yang_mengarah_ke_ip_privat_dihentikan_tanpa_permintaan_http(): void
    {
        $this->network->dns['web.jemberkab.go.id'] = ['93.184.216.34', '10.0.0.5'];
        Http::fake();

        $target = $this->scan();

        $this->assertSame(ScanTargetStatus::Failed, $target->status);
        $this->assertStringContainsString('10.0.0.5', $target->error_message);
        $this->assertStringContainsString('SSRF', $target->error_message);
        Http::assertNothingSent();
        $this->assertSame(ObservationStatus::Fail, $this->observation($target, 'dns')->status);
    }

    public function test_domain_yang_tidak_ada_gagal_diperiksa(): void
    {
        $this->network->dns['web.jemberkab.go.id'] = [];
        Http::fake();

        $target = $this->scan();

        $this->assertSame(ScanTargetStatus::Failed, $target->status);
        $this->assertStringContainsString('tidak ditemukan di DNS', $target->error_message);
        Http::assertNothingSent();
    }

    public function test_dns_error_dicatat_error_dan_target_gagal(): void
    {
        $this->network->dns['web.jemberkab.go.id'] = FakeNetwork::dnsFailure();

        $target = $this->scan();

        $this->assertSame(ScanTargetStatus::Failed, $target->status);
        $this->assertSame(ObservationStatus::Error, $this->observation($target, 'dns')->status);
    }

    public function test_website_tanpa_https_menghasilkan_no_https(): void
    {
        FakeNetwork::http([
            self::HOME => 'refused',
            'http://web.jemberkab.go.id/' => Http::response('<title>Tanpa HTTPS</title>', 200),
        ]);

        $target = $this->scan();

        $this->assertSame(ScanTargetStatus::Completed, $target->status);
        $keys = $target->findings->pluck('finding_key')->all();
        $this->assertContains('no-https', $keys);
        $this->assertContains('http-not-redirected', $keys);
        $this->assertNotContains('missing-hsts', $keys);
        $this->assertSame(ObservationStatus::NotApplicable, $this->observation($target, 'tls-certificate')->status);
        $this->assertSame(ObservationStatus::NotApplicable, $this->observation($target, 'header-hsts')->status);
        $this->assertSame(11, $target->riskItems->firstWhere('finding_key', 'no-https')->inherent_risk);
    }

    public function test_https_timeout_dicatat_error_bukan_temuan(): void
    {
        FakeNetwork::http([
            self::HOME => 'timeout',
            'http://web.jemberkab.go.id/' => Http::response('<title>Lambat</title>', 200),
        ]);

        $target = $this->scan();

        $this->assertSame(ScanTargetStatus::Partial, $target->status);
        $this->assertSame(ObservationStatus::Error, $this->observation($target, 'https')->status);
        $this->assertNotContains('no-https', $target->findings->pluck('finding_key')->all());

        // HTTPS belum terbukti tidak ada, sehingga HSTS dan cookie tidak boleh N/A maupun PASS (bagian 22.2)
        foreach (['header-hsts', 'cookie-security', 'tls-certificate'] as $key) {
            $this->assertSame(ObservationStatus::Error, $this->observation($target, $key)->status, $key);
        }

        $this->assertStringContainsString('waktu habis', $this->observation($target, 'header-hsts')->summary);
    }

    public function test_website_yang_tidak_dapat_diakses_gagal_diperiksa(): void
    {
        FakeNetwork::http([
            self::HOME => 'timeout',
            'http://web.jemberkab.go.id/' => 'timeout',
        ]);

        $target = $this->scan();

        $this->assertSame(ScanTargetStatus::Failed, $target->status);
        $this->assertStringContainsString('Website tidak dapat diakses', $target->error_message);
    }

    public function test_redirect_ke_domain_lain_tidak_diikuti(): void
    {
        FakeNetwork::http([
            self::HOME => Http::response('', 302, ['Location' => 'https://situs-lain.com/']),
            'http://web.jemberkab.go.id/' => Http::response('', 301, ['Location' => self::HOME]),
        ]);

        $target = $this->scan();

        Http::assertNotSent(fn ($request) => str_contains($request->url(), 'situs-lain.com'));
        $this->assertSame(ObservationStatus::NotAssessed, $this->observation($target, 'header-hsts')->status);
        $this->assertStringContainsString('tidak diikuti', $this->observation($target, 'http-status')->summary);
    }

    public function test_redirect_ke_subdomain_lain_yang_diizinkan_tidak_diikuti_dan_tujuannya_dicatat(): void
    {
        FakeNetwork::http([
            self::HOME => Http::response('', 302, ['Location' => 'https://portal.jemberkab.go.id/login', 'Set-Cookie' => 'PHPSESSID=abc; path=/']),
            'http://web.jemberkab.go.id/' => Http::response('', 301, ['Location' => self::HOME]),
            'https://portal.jemberkab.go.id/login' => Http::response('<title>Portal</title>', 200, self::secureHeaders()),
        ]);

        $target = $this->scan();

        // Bagian 22.11: host lain tidak diikuti walaupun domainnya diizinkan
        Http::assertNotSent(fn ($request) => str_contains($request->url(), 'portal.jemberkab.go.id'));

        // Respons redirect bukan halaman website: header dan cookie NOT ASSESSED, bukan PASS maupun FAIL
        foreach (['header-hsts', 'header-csp', 'header-x-frame-options', 'header-x-content-type-options', 'header-referrer-policy', 'cookie-security'] as $key) {
            $this->assertSame(ObservationStatus::NotAssessed, $this->observation($target, $key)->status, $key);
        }

        $this->assertStringContainsString('https://portal.jemberkab.go.id/login', $this->observation($target, 'cookie-security')->summary);
        $this->assertEmpty(array_intersect(['missing-hsts', 'missing-csp', 'insecure-cookie'], $target->findings->pluck('finding_key')->all()));

        // Alamat tujuan dicatat di evidence supaya dapat diperiksa sebagai target terpisah
        $status = $this->observation($target, 'http-status');
        $this->assertSame('https://portal.jemberkab.go.id/login', $status->raw['stopped_target']);
        $this->assertStringContainsString('Periksa portal.jemberkab.go.id sebagai target terpisah', $status->summary);
        $this->assertSame('https://portal.jemberkab.go.id/login', $target->overview['redirect_target']);
    }

    public function test_redirect_ke_awalan_www_diikuti_dengan_pemeriksaan_ip_ulang(): void
    {
        FakeNetwork::http([
            self::HOME => Http::response('', 301, ['Location' => 'https://www.web.jemberkab.go.id/']),
            'http://web.jemberkab.go.id/' => Http::response('', 301, ['Location' => self::HOME]),
            'https://www.web.jemberkab.go.id/' => Http::response('<title>Dinas</title>', 200, self::secureHeaders()),
        ]);
        $this->network->dns['www.web.jemberkab.go.id'] = ['93.184.216.35'];

        $target = $this->scan();

        $this->assertSame('https://www.web.jemberkab.go.id/', $target->overview['final_url']);
        $this->assertNull($target->overview['redirect_target']);
        $this->assertSame(ObservationStatus::Pass, $this->observation($target, 'header-hsts')->status);
        $this->assertSame(ObservationStatus::Pass, $this->observation($target, 'cookie-security')->status);
    }

    public function test_redirect_dari_www_ke_host_tanpa_www_diikuti(): void
    {
        FakeNetwork::http([
            'https://www.web.jemberkab.go.id/' => Http::response('', 301, ['Location' => self::HOME]),
            'http://www.web.jemberkab.go.id/' => Http::response('', 301, ['Location' => 'https://www.web.jemberkab.go.id/']),
            self::HOME => Http::response('<title>Dinas</title>', 200, self::secureHeaders()),
        ]);

        $target = $this->scan('https://www.web.jemberkab.go.id');

        $this->assertSame(self::HOME, $target->overview['final_url']);
        $this->assertSame(ObservationStatus::Pass, $this->observation($target, 'header-csp')->status);
    }

    public function test_redirect_ke_awalan_www_yang_mengarah_ke_ip_privat_diblokir(): void
    {
        FakeNetwork::http([
            self::HOME => Http::response('', 301, ['Location' => 'https://www.web.jemberkab.go.id/']),
            'http://web.jemberkab.go.id/' => Http::response('<title>HTTP</title>', 200),
            'https://www.web.jemberkab.go.id/' => Http::response('<title>Internal</title>', 200),
        ]);
        $this->network->dns['www.web.jemberkab.go.id'] = ['10.0.0.5'];

        $this->scan();

        Http::assertNotSent(fn ($request) => str_contains($request->url(), 'www.web.jemberkab.go.id'));
    }

    public function test_cookie_dari_redirect_https_yang_tidak_diikuti_tidak_dinilai(): void
    {
        FakeNetwork::http([
            'http://web.jemberkab.go.id/' => Http::response('<title>HTTP</title>', 200),
            self::HOME => Http::response('', 302, ['Location' => 'https://portal.jemberkab.go.id/', 'Set-Cookie' => 'PHPSESSID=abc; path=/']),
        ]);

        $target = $this->scan('http://web.jemberkab.go.id');

        $cookie = $this->observation($target, 'cookie-security');
        $this->assertSame(ObservationStatus::NotAssessed, $cookie->status);
        $this->assertStringContainsString('https://portal.jemberkab.go.id/', $cookie->summary);
        $this->assertSame(ObservationStatus::NotAssessed, $this->observation($target, 'header-hsts')->status);
        $this->assertNull($target->findings->firstWhere('finding_key', 'insecure-cookie'));
    }

    public function test_hsts_dinilai_pada_respons_https_yang_mengalihkan_ke_http(): void
    {
        FakeNetwork::http([
            'http://web.jemberkab.go.id/' => Http::response('<title>HTTP</title>', 200),
            self::HOME => Http::response('', 301, ['Location' => 'http://web.jemberkab.go.id/']),
        ]);

        $target = $this->scan('http://web.jemberkab.go.id');

        // HTTPS merespons (tidak ERROR), tetapi respons HTTPS terakhir tidak memasang HSTS
        $this->assertSame(ObservationStatus::Fail, $this->observation($target, 'header-hsts')->status);
        $this->assertSame(self::HOME, $target->findings->firstWhere('finding_key', 'missing-hsts')->evidences->first()->endpoint);
    }

    public function test_host_sama_atau_beda_awalan_www_dianggap_satu_website(): void
    {
        $this->assertTrue(SafeHttpClient::isSameSite('web.jemberkab.go.id', 'web.jemberkab.go.id'));
        $this->assertTrue(SafeHttpClient::isSameSite('web.jemberkab.go.id', 'WWW.web.jemberkab.go.id'));
        $this->assertTrue(SafeHttpClient::isSameSite('www.web.jemberkab.go.id', 'web.jemberkab.go.id.'));
        $this->assertFalse(SafeHttpClient::isSameSite('web.jemberkab.go.id', 'portal.jemberkab.go.id'));
        $this->assertFalse(SafeHttpClient::isSameSite('web.jemberkab.go.id', 'jemberkab.go.id'));
        $this->assertFalse(SafeHttpClient::isSameSite('web.jemberkab.go.id', 'wwwweb.jemberkab.go.id'));
    }

    public function test_halaman_blokir_waf_tidak_dinilai(): void
    {
        FakeNetwork::http([
            self::HOME => Http::response('<title>Attention Required! | Cloudflare</title>', 403, ['cf-ray' => '8abc', 'Server' => 'cloudflare']),
            'http://web.jemberkab.go.id/' => Http::response('', 301, ['Location' => self::HOME]),
        ]);

        $target = $this->scan();

        foreach (['header-hsts', 'header-csp', 'cookie-security', 'exposure-files', 'directory-listing'] as $key) {
            $this->assertSame(ObservationStatus::NotAssessed, $this->observation($target, $key)->status, $key);
        }

        $this->assertCount(0, $target->findings);
        $this->assertTrue($target->overview['waf_blocked']);
        $this->assertStringContainsString('allowlist', $this->observation($target, 'http-status')->summary);
    }

    public function test_title_halaman_waf_tidak_dipakai_sebagai_nama_aset(): void
    {
        // Kasus nyata Cloudflare "Just a moment...": TLS tetap dapat dinilai dan menjadi baris Risk Register
        FakeNetwork::http([
            self::HOME => Http::response('<html><head><title>Just a moment...</title></head><body class="cf-chl-">challenge-platform</body></html>', 403, ['Server' => 'cloudflare', 'cf-ray' => '8abc']),
            'http://web.jemberkab.go.id/' => Http::response('', 301, ['Location' => self::HOME]),
        ]);
        $this->network->protocols['TLSv1.1'] = 'accepted';

        $target = $this->scan(mode: ScanMode::Quick);

        $item = $target->riskItems->firstWhere('finding_key', 'tls-legacy-protocol');
        $this->assertSame('Website web.jemberkab.go.id', $item->asset);

        $this->get(route('targets.show', $target))
            ->assertOk()
            ->assertSee('Just a moment... (halaman WAF/CDN)')
            ->assertSee('Tambahkan pengecualian (allowlist)');
    }

    public function test_pemeriksaan_yang_error_tidak_menghentikan_pemeriksaan_lain(): void
    {
        FakeNetwork::http([
            self::HOME => Http::response('<title>Aman</title>', 200, self::secureHeaders()),
            'http://web.jemberkab.go.id/' => Http::response('', 301, ['Location' => self::HOME]),
        ]);
        $this->network->tls = new RuntimeException('Kesalahan tak terduga');

        $target = $this->scan();

        $this->assertSame(ScanTargetStatus::Partial, $target->status);
        $this->assertSame(ObservationStatus::Error, $this->observation($target, 'tls')->status);
        // Pemeriksaan setelah TLS tetap berjalan
        $this->assertSame(ObservationStatus::Pass, $this->observation($target, 'exposure-files')->status);
        $this->assertSame('done', collect($target->progress)->firstWhere('key', 'risk-assessment')['status']);
    }

    public function test_batas_waktu_habis_mencatat_error(): void
    {
        config(['siprika.scan.target_timeout' => 0]);
        Http::fake();

        $target = $this->scan();

        $this->assertSame(ScanTargetStatus::Partial, $target->status);
        $this->assertStringContainsString('melewati batas waktu', $this->observation($target, 'target-validation')->summary);
        Http::assertNothingSent();
    }

    /**
     * @return array<string, array{array<string, mixed>, string, string}>
     */
    public static function tlsProvider(): array
    {
        return [
            'kedaluwarsa' => [['validFrom' => '-400 days', 'validTo' => '-5 days', 'verified' => false], 'tls-cert-invalid', 'sertifikat kedaluwarsa'],
            'hostname tidak cocok' => [['subjectAltNames' => ['lain.example.com'], 'verified' => false], 'tls-cert-invalid', 'tidak cocok dengan sertifikat'],
            'self-signed' => [['selfSigned' => true, 'chainLength' => 1, 'verified' => false], 'tls-cert-invalid', 'self-signed'],
            'penerbit tidak dikenali' => [['verified' => false, 'verifyError' => 'certificate verify failed'], 'tls-chain-incomplete', 'penerbit sertifikat tidak dikenali'],
            'intermediate tidak dikirim' => [['chainLength' => 1], 'tls-chain-incomplete', 'intermediate tidak dikirim'],
            'segera kedaluwarsa' => [['validFrom' => '-340 days', 'validTo' => '+20 days'], 'tls-cert-expiring', 'sisa'],
        ];
    }

    /**
     * @param  array<string, mixed>  $overrides
     */
    #[DataProvider('tlsProvider')]
    public function test_masalah_tls_dipetakan_ke_kunci_finding(array $overrides, string $key, string $detail): void
    {
        foreach (['validFrom', 'validTo'] as $field) {
            if (isset($overrides[$field])) {
                $overrides[$field] = CarbonImmutable::now()->modify($overrides[$field]);
            }
        }

        $this->network->tls = FakeNetwork::validCertificate('web.jemberkab.go.id', $overrides);
        FakeNetwork::http([
            self::HOME => Http::response('<title>TLS</title>', 200, self::secureHeaders()),
            'http://web.jemberkab.go.id/' => Http::response('', 301, ['Location' => self::HOME]),
        ]);

        $target = $this->scan();

        $finding = $target->findings->firstWhere('finding_key', $key);
        $this->assertNotNull($finding, "Finding {$key} tidak ditemukan");
        $this->assertStringContainsString($detail, $finding->evidences->first()->detail);
    }

    public function test_sertifikat_let_s_encrypt_yang_diperbarui_otomatis_bukan_temuan(): void
    {
        // Sertifikat 90 hari dengan sisa 25 hari: masih di atas 1/4 masa berlaku
        $this->network->tls = FakeNetwork::validCertificate('web.jemberkab.go.id', [
            'validFrom' => CarbonImmutable::now()->subDays(65),
            'validTo' => CarbonImmutable::now()->addDays(25),
        ]);
        FakeNetwork::http([
            self::HOME => Http::response('<title>TLS</title>', 200, self::secureHeaders()),
            'http://web.jemberkab.go.id/' => Http::response('', 301, ['Location' => self::HOME]),
        ]);

        $target = $this->scan();

        $this->assertSame(ObservationStatus::Pass, $this->observation($target, 'tls-expiry')->status);
        $this->assertNotContains('tls-cert-expiring', $target->findings->pluck('finding_key')->all());
    }

    public function test_tls_lama_yang_tidak_bisa_diuji_dicatat_not_assessed(): void
    {
        $this->network->protocols['TLSv1.0'] = 'unsupported';
        $this->network->protocols['TLSv1.1'] = 'unsupported';
        FakeNetwork::http([
            self::HOME => Http::response('<title>TLS</title>', 200, self::secureHeaders()),
            'http://web.jemberkab.go.id/' => Http::response('', 301, ['Location' => self::HOME]),
        ]);

        $target = $this->scan();

        $this->assertSame(ObservationStatus::NotAssessed, $this->observation($target, 'tls-protocol')->status);
        $this->assertSame(ScanTargetStatus::Completed, $target->status);
    }

    public function test_mode_cepat_hanya_menjalankan_pemeriksaan_mode_cepat(): void
    {
        $this->fakeVulnerableSite();

        $target = $this->scan(mode: ScanMode::Quick);

        $this->assertSame(ScanTargetStatus::Completed, $target->status);

        // Progress hanya berisi tahap Mode Cepat
        $this->assertSame(
            ['target-validation', 'http-info', 'security-headers', 'cookie-security', 'technology', 'tls', 'exposure', 'nuclei', 'ai-analysis', 'risk-assessment'],
            array_column($target->progress, 'key'),
        );

        // Pemeriksaan khusus Mode Standar tidak dijalankan tetapi tetap terlihat di Coverage
        foreach (['ports', 'testssl', 'whatweb', 'zap-passive'] as $key) {
            $observation = $this->observation($target, $key);
            $this->assertNotNull($observation, $key);
            $this->assertSame(ObservationStatus::NotAssessed, $observation->status, $key);
            $this->assertStringContainsString('Mode Cepat', $observation->summary, $key);
        }

        $this->assertNull($this->observation($target, 'service-version'));
        $this->assertArrayNotHasKey('open_ports', $target->overview);

        // Exposure terbatas: path umum diperiksa, path lain tidak
        Http::assertSent(fn ($request) => $request->url() === 'https://web.jemberkab.go.id/.env');
        Http::assertSent(fn ($request) => $request->url() === 'https://web.jemberkab.go.id/uploads/');
        Http::assertNotSent(fn ($request) => str_contains($request->url(), 'wp-config.php.bak'));
        Http::assertNotSent(fn ($request) => str_ends_with($request->url(), '/backup/'));
        $this->assertStringContainsString('Mode Cepat', $this->observation($target, 'exposure-files')->summary);

        // Finding dan penilaian risiko tetap sama dengan Mode Standar untuk pemeriksaan yang dijalankan
        $keys = $target->findings->pluck('finding_key')->all();
        $this->assertContains('exposed-sensitive-file', $keys);
        $this->assertContains('directory-listing', $keys);
        $this->assertContains('missing-hsts', $keys);
        $this->assertSame(23, $target->riskItems->firstWhere('finding_key', 'exposed-sensitive-file')->inherent_risk);
    }

    public function test_mode_cepat_memakai_batas_waktu_sendiri(): void
    {
        config(['siprika.scan.quick_target_timeout' => 600, 'siprika.scan.target_timeout' => 1200]);
        $this->assertSame(600, ScanMode::Quick->timeout());
        $this->assertSame(1200, ScanMode::Standard->timeout());

        config(['siprika.scan.quick_target_timeout' => 0]);
        Http::fake();

        $target = $this->scan(mode: ScanMode::Quick);

        $this->assertSame(ScanTargetStatus::Partial, $target->status);
        $this->assertStringContainsString('melewati batas waktu', $this->observation($target, 'target-validation')->summary);
        Http::assertNothingSent();
    }

    public function test_exposure_yang_sebagian_gagal_diperiksa_dicatat_error_bukan_pass(): void
    {
        FakeNetwork::http([
            self::HOME => Http::response('<title>Aman</title>', 200, self::secureHeaders()),
            'http://web.jemberkab.go.id/' => Http::response('', 301, ['Location' => self::HOME]),
            'https://web.jemberkab.go.id/.env' => 'timeout',
        ]);

        $target = $this->scan(mode: ScanMode::Quick);

        $observation = $this->observation($target, 'exposure-files');
        $this->assertSame(ObservationStatus::Error, $observation->status);
        $this->assertStringContainsString('1 path gagal diperiksa', $observation->summary);
        $this->assertSame(ScanTargetStatus::Partial, $target->status);
    }

    public function test_coverage_mode_cepat_menampilkan_batasan(): void
    {
        $this->fakeVulnerableSite();
        $target = $this->scan(mode: ScanMode::Quick);

        $this->get(route('targets.show', ['scanTarget' => $target, 'tab' => 'coverage']))
            ->assertOk()
            ->assertSee('Mode Cepat: hanya halaman utama yang diperiksa')
            ->assertSee('hanya tersedia pada Mode Standar');

        $standard = $this->scan();
        $this->get(route('targets.show', ['scanTarget' => $standard, 'tab' => 'coverage']))
            ->assertOk()
            ->assertDontSee('Mode Cepat: hanya halaman utama yang diperiksa');
    }

    public function test_log_laravel_yang_terbuka_terdeteksi_dan_isinya_disamarkan(): void
    {
        // Kasus nyata: storage/logs/laravel.log dapat diunduh publik karena document root salah
        $log = "[2026-09-25 18:15:39] production.ERROR: SQLSTATE[HY000] [1045] Access denied for user 'sakip'@'localhost' (using password: YES) password=RahasiaDb123 {\"exception\":\"[object]\"}\n#0 /home/esakip/vendor/laravel/framework/src/Illuminate/Database/Connection.php(822)\n";
        FakeNetwork::http([
            self::HOME => Http::response('<title>E-SAKIP</title>', 200, self::secureHeaders()),
            'http://web.jemberkab.go.id/' => Http::response('', 301, ['Location' => self::HOME]),
            'https://web.jemberkab.go.id/storage/logs/laravel.log' => Http::response($log, 200, ['Content-Type' => 'text/plain']),
        ]);

        $target = $this->scan(mode: ScanMode::Quick);

        $finding = $target->findings->firstWhere('finding_key', 'exposed-sensitive-file');
        $this->assertNotNull($finding);
        $evidence = $finding->evidences->first();
        $this->assertSame('Log aplikasi Laravel dapat diakses di /storage/logs/laravel.log', $evidence->detail);
        $this->assertStringContainsString('production.ERROR', $evidence->raw['snippet']);
        $this->assertStringNotContainsString('RahasiaDb123', $evidence->raw['snippet']);
        $this->assertLessThanOrEqual(200, mb_strlen($evidence->raw['snippet']));
        $this->assertSame(23, $target->riskItems->firstWhere('finding_key', 'exposed-sensitive-file')->inherent_risk);
    }

    public function test_status_200_tanpa_isi_log_bukan_temuan(): void
    {
        // Contoh halaman 404 kustom yang menjawab status 200
        FakeNetwork::http([
            self::HOME => Http::response('<title>E-SAKIP</title>', 200, self::secureHeaders()),
            'http://web.jemberkab.go.id/' => Http::response('', 301, ['Location' => self::HOME]),
            'https://web.jemberkab.go.id/storage/logs/laravel.log' => Http::response('<html>Halaman tidak ditemukan</html>', 200),
        ]);
        $this->assertNull($this->scan(mode: ScanMode::Quick)->findings->firstWhere('finding_key', 'exposed-sensitive-file'));
    }

    public function test_probe_tls_yang_gagal_sesaat_diulang_sekali(): void
    {
        FakeNetwork::http([
            self::HOME => Http::response('<title>TLS</title>', 200, self::secureHeaders()),
            'http://web.jemberkab.go.id/' => Http::response('', 301, ['Location' => self::HOME]),
        ]);
        // Kasus nyata: koneksi TLS 1.0 terputus sekali, percobaan kedua ditolak server dengan benar
        $this->network->protocols['TLSv1.0'] = ['error', 'rejected'];

        $target = $this->scan(mode: ScanMode::Quick);

        $this->assertSame(ObservationStatus::Pass, $this->observation($target, 'tls-protocol')->status);
        $this->assertSame(ScanTargetStatus::Completed, $target->status);

        // Gagal dua kali tetap ERROR
        $this->network->protocols['TLSv1.0'] = ['error', 'error'];
        $target = $this->scan(mode: ScanMode::Quick);
        $this->assertSame(ObservationStatus::Error, $this->observation($target, 'tls-protocol')->status);
    }

    public function test_pemeriksaan_sertifikat_tls_yang_timeout_sesaat_diulang_sekali(): void
    {
        FakeNetwork::http([
            self::HOME => Http::response('<title>TLS</title>', 200, self::secureHeaders()),
            'http://web.jemberkab.go.id/' => Http::response('', 301, ['Location' => self::HOME]),
        ]);
        // Pesan asli Windows saat website lambat menjawab (errno 10060)
        $timeout = HttpFailure::fromSocketError(10060, 'A connection attempt failed because the connected party did not properly respond after a period of time');

        // Kasus nyata e-sakip: percobaan pertama timeout, percobaan kedua berhasil
        $this->network->tls = [$timeout, FakeNetwork::validCertificate('web.jemberkab.go.id')];
        $target = $this->scan(mode: ScanMode::Quick);
        $this->assertSame(ObservationStatus::Pass, $this->observation($target, 'tls-certificate')->status);
        $this->assertSame(ScanTargetStatus::Completed, $target->status);

        // Timeout dua kali: ERROR dengan penyebab yang benar, bukan "koneksi ditolak"
        $this->network->tls = [$timeout, $timeout];
        $target = $this->scan(mode: ScanMode::Quick);
        $this->assertSame(ObservationStatus::Error, $this->observation($target, 'tls-certificate')->status);
        $this->assertStringContainsString('Koneksi TLS gagal (waktu habis)', $this->observation($target, 'tls-certificate')->summary);

        // Handshake TLS yang ditolak bukan masalah jaringan, tidak diulang
        $this->network->tls = [new HttpFailure(HttpFailure::TLS, 'handshake failure'), FakeNetwork::validCertificate('web.jemberkab.go.id')];
        $target = $this->scan(mode: ScanMode::Quick);
        $this->assertSame(ObservationStatus::Error, $this->observation($target, 'tls-certificate')->status);
    }

    public function test_jenis_kegagalan_koneksi_dikenali_dari_pesan_dan_nomor_error_windows_maupun_linux(): void
    {
        $this->assertSame(HttpFailure::TIMEOUT, HttpFailure::fromSocketError(10060, 'x')->kind);
        $this->assertSame(HttpFailure::TIMEOUT, HttpFailure::fromSocketError(110, 'Connection timed out')->kind);
        $this->assertSame(HttpFailure::REFUSED, HttpFailure::fromSocketError(10061, 'No connection could be made because the target machine actively refused it')->kind);
        $this->assertSame(HttpFailure::REFUSED, HttpFailure::fromSocketError(111, 'Connection refused')->kind);
        $this->assertSame(HttpFailure::TIMEOUT, HttpFailure::fromMessage('A connection attempt failed because the connected party did not properly respond after a period of time')->kind);
        $this->assertSame(HttpFailure::OTHER, HttpFailure::fromSocketError(10065, 'A socket operation was attempted to an unreachable host')->kind);
        $this->assertSame('waktu habis', HttpFailure::fromSocketError(10060, 'x')->kindLabel());
    }

    public function test_deteksi_teknologi_tidak_tertipu_nama_fungsi_javascript(): void
    {
        $body = '<html><head><title>E-SAKIP</title></head><body><script>function openSidebar() {}</script></body></html>';
        FakeNetwork::http([
            self::HOME => Http::response($body, 200, self::secureHeaders()),
            'http://web.jemberkab.go.id/' => Http::response('', 301, ['Location' => self::HOME]),
        ]);

        $target = $this->scan(mode: ScanMode::Quick);

        $this->assertNotContains('OpenSID', array_column($target->overview['technologies'], 'name'));
        $this->assertNull($target->overview['cms']);

        $html = '<footer>Powered by OpenSID v24.05</footer>';
        $this->assertContains('OpenSID', array_column(Fingerprint::technologies(new HttpExchange(self::HOME, 200, [], $html)), 'name'));
    }

    public function test_tool_eksternal_memakai_url_yang_dapat_diakses(): void
    {
        // Kasus nyata scanme.nmap.org: input tanpa skema dianggap https://, tetapi website hanya melayani http://
        FakeNetwork::http([
            self::HOME => 'refused',
            'http://web.jemberkab.go.id/' => Http::response('<title>Hanya HTTP</title>', 200),
        ]);
        config(['siprika.tools.nuclei.command' => 'nuclei', 'siprika.tools.whatweb.command' => 'whatweb']);
        Process::fake(['*' => Process::result('')]);

        $target = $this->scan();

        Process::assertRan(fn (PendingProcess $process) => str_starts_with(self::commandOf($process), 'nuclei -u http://web.jemberkab.go.id/ '));
        Process::assertRan(fn (PendingProcess $process) => str_ends_with(self::commandOf($process), '--log-json=whatweb.json http://web.jemberkab.go.id/'));
        Process::assertNotRan(fn (PendingProcess $process) => str_contains(self::commandOf($process), 'https://web.jemberkab.go.id'));
        $this->assertSame('http://web.jemberkab.go.id/', $target->observations->firstWhere('check_key', 'nuclei')->raw['url']);
    }

    public function test_tool_eksternal_tidak_mengikuti_redirect_dan_tidak_dijalankan_jika_dns_berpindah_ke_ip_privat(): void
    {
        FakeNetwork::http([
            self::HOME => Http::response('<title>Web</title>', 200, self::secureHeaders()),
            'http://web.jemberkab.go.id/' => Http::response('', 301, ['Location' => self::HOME]),
        ]);
        config(['siprika.tools.nuclei.command' => 'nuclei', 'siprika.tools.whatweb.command' => 'whatweb']);
        Process::fake(['*' => Process::result('')]);

        // DNS rebinding: publik saat divalidasi, lalu berpindah ke IP privat sebelum tool eksternal berjalan
        $lookups = 0;
        $this->network->dns['web.jemberkab.go.id'] = function () use (&$lookups) {
            return ++$lookups === 1 ? ['93.184.216.34'] : ['169.254.169.254'];
        };

        $target = $this->scan();

        Process::assertNothingRan();
        foreach (['nuclei', 'whatweb'] as $key) {
            $observation = $target->observations->firstWhere('check_key', $key);
            $this->assertSame(ObservationStatus::Error, $observation->status, $key);
            $this->assertStringContainsString('169.254.169.254', $observation->summary);
        }

        // DNS tetap publik: tool berjalan tanpa mengikuti redirect sendiri
        $this->network->dns['web.jemberkab.go.id'] = ['93.184.216.34'];
        $this->scan();

        Process::assertRan(fn (PendingProcess $process) => str_contains(self::commandOf($process), ' -dr '));
        Process::assertRan(fn (PendingProcess $process) => str_contains(self::commandOf($process), '--follow-redirect=never'));
    }

    public function test_testssl_memakai_port_https_dari_url_target(): void
    {
        FakeNetwork::http([
            'https://web.jemberkab.go.id:8443/' => Http::response('<title>Port lain</title>', 200, self::secureHeaders()),
            'http://web.jemberkab.go.id/' => 'refused',
        ]);
        config(['siprika.tools.testssl.command' => 'testssl.sh']);
        Process::fake(function (PendingProcess $process) {
            file_put_contents($process->path.DIRECTORY_SEPARATOR.'testssl.json', (string) file_get_contents(base_path('tests/Fixtures/testssl-diskominfo.json')));

            return Process::result('');
        });

        $target = $this->scan('https://web.jemberkab.go.id:8443');

        Process::assertRan(fn (PendingProcess $process) => str_ends_with(self::commandOf($process), 'web.jemberkab.go.id:8443'));
        $evidence = $target->findings->firstWhere('finding_key', 'tls-legacy-protocol')->evidences->firstWhere('source', 'testssl');
        $this->assertSame('https://web.jemberkab.go.id:8443/', $evidence->endpoint);
    }

    public function test_respons_besar_hanya_dibaca_sampai_batas(): void
    {
        config(['siprika.scan.max_body_bytes' => 1024]);
        FakeNetwork::http([
            self::HOME => Http::response('<title>Besar</title>'.str_repeat('x', 50000), 200, self::secureHeaders()),
            'http://web.jemberkab.go.id/' => Http::response('', 301, ['Location' => self::HOME]),
        ]);
        $this->app->instance(SafeHttpClient::class, $client = new SafeHttpClient($this->network));

        $response = $client->get('https://web.jemberkab.go.id');

        $this->assertSame(1024, strlen($response->body));
        $this->assertSame('Besar', $response->title());
    }

    public function test_hsts_dari_nuclei_pada_respons_http_diabaikan(): void
    {
        // Header HSTS hanya berlaku pada respons HTTPS (bagian 23.1)
        $line = fn (string $url) => json_encode(['template-id' => 'http-missing-security-headers', 'matcher-name' => 'strict-transport-security', 'info' => ['name' => 'HTTP Missing Security Headers', 'severity' => 'info', 'tags' => ['misconfig']], 'matched-at' => $url]);

        $this->assertSame([], NucleiParser::parse($line('http://web.jemberkab.go.id/'))['findings']);
        $this->assertSame('missing-hsts', NucleiParser::parse($line('https://web.jemberkab.go.id/'))['findings'][0]->key);
    }

    public function test_halaman_hasil_menampilkan_semua_tab(): void
    {
        $this->fakeVulnerableSite();
        $target = $this->scan();

        $this->get(route('targets.show', $target))->assertOk()->assertSee('Dinas Contoh')->assertSee('WordPress');
        $this->get(route('targets.show', ['scanTarget' => $target, 'tab' => 'security']))->assertOk()->assertSee('Content-Security-Policy')->assertSee('FAIL');
        $this->get(route('targets.show', ['scanTarget' => $target, 'tab' => 'findings']))->assertOk()->assertSee('File sensitif dapat diakses publik')->assertSee('APP_KEY=***');
        $this->get(route('targets.show', ['scanTarget' => $target, 'tab' => 'risk']))->assertOk()->assertSee('Not Acceptable')->assertSee('23');
        $this->get(route('targets.show', ['scanTarget' => $target, 'tab' => 'coverage']))->assertOk()->assertSee('NOT ASSESSED')->assertSee('Nuclei');
    }

    public function test_parameter_tab_yang_tidak_valid_kembali_ke_overview(): void
    {
        $this->fakeVulnerableSite();
        $target = $this->scan();

        foreach (['tidakada', '', ['x']] as $tab) {
            $this->get(route('targets.show', ['scanTarget' => $target, 'tab' => $tab]))
                ->assertOk()
                ->assertSee('Waktu Pemeriksaan');
        }
    }

    public function test_export_excel_dapat_diunduh(): void
    {
        $this->fakeVulnerableSite();
        $target = $this->scan();

        $this->get(route('scans.export', $target->batch))
            ->assertOk()
            ->assertDownload('Risk Register SIPRIKA - Batch '.$target->batch->id.'.xlsx');

        $this->get(route('targets.export', $target))
            ->assertOk()
            ->assertDownload('Risk Register SIPRIKA - web.jemberkab.go.id.xlsx');

        $this->assertSame(11, RiskRegisterItem::count());
    }

    public function test_isi_csp_ditampilkan_dan_csp_tanpa_pembatasan_script_diberi_catatan(): void
    {
        $headers = self::secureHeaders();
        $headers['Content-Security-Policy'] = 'upgrade-insecure-requests';
        FakeNetwork::http([
            'https://web.jemberkab.go.id/' => Http::response('<title>Web</title>', 200, $headers),
            'http://web.jemberkab.go.id/' => Http::response('', 301, ['Location' => 'https://web.jemberkab.go.id/']),
        ]);

        $csp = $this->observation($this->scan(), 'header-csp');

        // Sesuai kriteria bagian 23 tetap PASS, tetapi tidak terbaca seolah membatasi script
        $this->assertSame(ObservationStatus::Pass, $csp->status);
        $this->assertSame('Content-Security-Policy: upgrade-insecure-requests (tanpa default-src atau script-src, sehingga tidak membatasi sumber script)', $csp->summary);

        $headers['Content-Security-Policy'] = "default-src 'self'; frame-ancestors 'self'";
        FakeNetwork::http(['https://web.jemberkab.go.id/' => Http::response('<title>Web</title>', 200, $headers), 'http://web.jemberkab.go.id/' => Http::response('', 301, ['Location' => 'https://web.jemberkab.go.id/'])]);
        $this->assertSame("Content-Security-Policy: default-src 'self'; frame-ancestors 'self'", $this->observation($this->scan(), 'header-csp')->summary);
    }
}
