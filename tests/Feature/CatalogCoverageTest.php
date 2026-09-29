<?php

namespace Tests\Feature;

use App\Enums\ObservationStatus;
use App\Enums\ScanMode;
use App\Models\ScanTarget;
use App\Scanner\CatalogCoverage;
use App\Scanner\Checks\SecurityHeadersCheck;
use App\Scanner\ScanContext;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Process\PendingProcess;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Process;
use RuntimeException;
use Tests\Support\FakeNetwork;
use Tests\Support\InteractsWithScanner;
use Tests\TestCase;

/**
 * Coverage per kunci katalog (bagian 22.10): kunci yang tidak diperiksa dicatat NOT ASSESSED, bukan PASS.
 */
class CatalogCoverageTest extends TestCase
{
    use InteractsWithScanner;
    use RefreshDatabase;

    private const HOME = 'https://web.jemberkab.go.id/';

    protected function setUp(): void
    {
        parent::setUp();

        $this->setUpScanner();
    }

    private function fakeSecureSite(): void
    {
        FakeNetwork::http([
            self::HOME => Http::response('<title>Dinas</title>', 200, self::secureHeaders()),
            'http://web.jemberkab.go.id/' => Http::response('', 301, ['Location' => self::HOME]),
        ]);
    }

    /**
     * @return array<string, array{key: string, title: string, status: ObservationStatus, assessors: list<string>, note: string}>
     */
    private function coverage(ScanTarget $target): array
    {
        return collect(CatalogCoverage::for($target))->keyBy('key')->all();
    }

    /**
     * Output JSONL Nuclei palsu.
     *
     * @param  list<array<string, mixed>>  $lines
     */
    private static function fakeNuclei(array $lines = []): void
    {
        config(['siprika.tools.nuclei.command' => 'nuclei']);
        Process::fake(['*' => Process::result(implode("\n", array_map('json_encode', $lines)))]);
    }

    private static function missingHeader(string $matcher, string $url = self::HOME): array
    {
        return ['template-id' => 'http-missing-security-headers', 'matcher-name' => $matcher, 'info' => ['name' => 'HTTP Missing Security Headers', 'severity' => 'info', 'tags' => ['misconfig', 'headers']], 'matched-at' => $url];
    }

    public function test_semua_kunci_katalog_punya_status_dan_pass_hanya_jika_ada_pemeriksanya(): void
    {
        $this->fakeSecureSite();

        $coverage = $this->coverage($this->scan(mode: ScanMode::Quick));

        $this->assertSame(array_keys(config('siprika_scanner.catalog_coverage')), array_keys($coverage));

        foreach ($coverage as $key => $row) {
            if ($row['status'] === ObservationStatus::Pass) {
                $this->assertNotEmpty($row['assessors'], $key);
            }
        }

        foreach (['missing-hsts', 'missing-csp', 'insecure-cookie', 'tls-cert-invalid', 'server-version-disclosure', 'directory-listing', 'exposed-sensitive-file'] as $key) {
            $this->assertSame(ObservationStatus::Pass, $coverage[$key]['status'], $key);
        }

        // Tanpa Nuclei dan testssl.sh (tidak ada di Mode Cepat) tidak ada yang menilai cipher lemah
        $this->assertSame(ObservationStatus::NotAssessed, $coverage['tls-weak-cipher']['status']);
        $this->assertSame([], $coverage['tls-weak-cipher']['assessors']);
        $this->assertStringContainsString('Mode Cepat', $coverage['tls-weak-cipher']['note']);
    }

    public function test_tab_coverage_dan_findings_tidak_menyiratkan_website_aman(): void
    {
        $this->fakeSecureSite();
        $target = $this->scan(mode: ScanMode::Quick);
        $this->assertCount(0, $target->findings);

        $this->get(route('targets.show', ['scanTarget' => $target, 'tab' => 'coverage']))
            ->assertOk()
            ->assertSee('Kunci Katalog')
            ->assertSee('data-catalog-key="tls-weak-cipher"', false)
            ->assertSeeInOrder(['Cipher TLS lemah masih diterima', 'NOT ASSESSED']);

        $this->get(route('targets.show', ['scanTarget' => $target, 'tab' => 'findings']))
            ->assertOk()
            ->assertSee('Tidak ada finding')
            ->assertSee('1 dari 16 jenis temuan tidak diperiksa atau pemeriksaannya gagal');
    }

    public function test_nuclei_mencatat_kunci_yang_dinilai_sesuai_profil_mode(): void
    {
        $this->fakeSecureSite();
        self::fakeNuclei();

        $quick = $this->coverage($this->scan(mode: ScanMode::Quick));

        // Profil Cepat mencakup cipher lemah, tetapi tidak mencakup template cookie
        $this->assertSame(ObservationStatus::Pass, $quick['tls-weak-cipher']['status']);
        $this->assertSame(['Nuclei'], $quick['tls-weak-cipher']['assessors']);
        $this->assertSame('Nuclei menilai kunci ini dan tidak menemukan masalah.', $quick['tls-weak-cipher']['note']);
        $this->assertNotContains('Nuclei', $quick['insecure-cookie']['assessors']);
        $this->assertNotContains('Nuclei', $quick['directory-listing']['assessors']);

        $standard = $this->coverage($this->scan(mode: ScanMode::Standard));

        $this->assertContains('Nuclei', $standard['insecure-cookie']['assessors']);
        $this->assertNotContains('Nuclei', $standard['directory-listing']['assessors']);
    }

    public function test_nuclei_yang_gagal_tidak_membuat_kunci_pass(): void
    {
        $this->fakeSecureSite();
        config(['siprika.tools.nuclei.command' => 'nuclei']);
        Process::fake(['*' => Process::result('', 'nuclei: command not found', 1)]);

        $coverage = $this->coverage($this->scan(mode: ScanMode::Quick));

        $this->assertSame(ObservationStatus::Error, $coverage['tls-weak-cipher']['status']);
        $this->assertStringContainsString('command not found', $coverage['tls-weak-cipher']['note']);
        // Kunci yang juga dinilai pemeriksaan bawaan tetap PASS dari pemeriksaan bawaan
        $this->assertSame(ObservationStatus::Pass, $coverage['missing-csp']['status']);
    }

    public function test_testssl_mencatat_kunci_yang_dinilai(): void
    {
        $this->fakeSecureSite();
        config(['siprika.tools.testssl.command' => 'testssl.sh']);
        Process::fake(function (PendingProcess $process) {
            file_put_contents($process->path.DIRECTORY_SEPARATOR.'testssl.json', (string) file_get_contents(base_path('tests/Fixtures/testssl-diskominfo.json')));

            return Process::result('');
        });

        $target = $this->scan();
        $coverage = $this->coverage($target);

        $this->assertSame(['tls-chain-incomplete', 'tls-legacy-protocol', 'tls-weak-cipher'], $target->observations->firstWhere('check_key', 'testssl')->raw['assessed_keys']);
        $this->assertSame(ObservationStatus::Pass, $coverage['tls-weak-cipher']['status']);
        $this->assertSame(['testssl.sh'], $coverage['tls-weak-cipher']['assessors']);
    }

    public function test_halaman_blokir_waf_membuat_kunci_halaman_not_assessed_termasuk_hasil_nuclei(): void
    {
        FakeNetwork::http([
            self::HOME => Http::response('<title>Attention Required! | Cloudflare</title>', 403, ['cf-ray' => '8abc', 'Server' => 'cloudflare']),
            'http://web.jemberkab.go.id/' => Http::response('', 301, ['Location' => self::HOME]),
        ]);
        // Nuclei membaca halaman WAF yang sama dan melaporkan header yang tidak ada
        self::fakeNuclei([self::missingHeader('content-security-policy'), self::missingHeader('strict-transport-security')]);

        $target = $this->scan(mode: ScanMode::Quick);
        $coverage = $this->coverage($target);

        $this->assertEmpty(array_intersect(['missing-csp', 'missing-hsts'], $target->findings->pluck('finding_key')->all()));

        foreach (['missing-hsts', 'missing-csp', 'missing-x-frame-options', 'missing-referrer-policy', 'insecure-cookie', 'server-version-disclosure'] as $key) {
            $this->assertSame(ObservationStatus::NotAssessed, $coverage[$key]['status'], $key);
        }

        $nuclei = $target->observations->firstWhere('check_key', 'nuclei');
        $this->assertEqualsCanonicalizing(['missing-csp', 'missing-hsts'], array_keys($nuclei->raw['ignored_keys']));
        $this->assertNotContains('missing-csp', $nuclei->raw['assessed_keys']);
        $this->assertStringContainsString('diabaikan', $nuclei->summary);
        // Kunci TLS tetap dinilai Nuclei karena tidak bergantung pada isi halaman
        $this->assertContains('tls-weak-cipher', $nuclei->raw['assessed_keys']);
        // Path lain juga terblokir WAF: "tidak ada template yang cocok" tidak boleh menjadi PASS
        $this->assertNotContains('exposed-sensitive-file', $nuclei->raw['assessed_keys']);
        $this->assertSame(ObservationStatus::NotAssessed, $coverage['exposed-sensitive-file']['status']);
    }

    public function test_temuan_exposure_nuclei_tetap_disimpan_walaupun_halaman_utama_diblokir_waf(): void
    {
        FakeNetwork::http([
            self::HOME => Http::response('<title>Attention Required! | Cloudflare</title>', 403, ['cf-ray' => '8abc', 'Server' => 'cloudflare']),
            'http://web.jemberkab.go.id/' => Http::response('', 301, ['Location' => self::HOME]),
        ]);
        self::fakeNuclei([['template-id' => 'git-config', 'info' => ['name' => 'Git Config Disclosure', 'severity' => 'medium', 'tags' => ['exposure', 'config', 'git']], 'matched-at' => self::HOME.'.git/config']]);

        $target = $this->scan(mode: ScanMode::Quick);

        // Cocok berdasarkan isi file, jadi temuan tetap sah
        $this->assertSame(['nuclei'], $target->findings->firstWhere('finding_key', 'exposed-sensitive-file')->sources);
        $this->assertSame(ObservationStatus::Fail, $this->coverage($target)['exposed-sensitive-file']['status']);
    }

    public function test_temuan_header_nuclei_dibuang_jika_pemeriksaan_bawaan_menemukan_kontrol_lewat_meta_atau_frame_ancestors(): void
    {
        $headers = self::secureHeaders();
        // CSP lewat tag meta, clickjacking dicegah frame-ancestors (tanpa X-Frame-Options), Referrer-Policy lewat tag meta
        unset($headers['Content-Security-Policy'], $headers['X-Frame-Options'], $headers['Referrer-Policy']);
        $headers['Content-Security-Policy'] = "frame-ancestors 'self'";
        FakeNetwork::http([
            self::HOME => Http::response('<head><meta name="referrer" content="no-referrer"></head>', 200, $headers),
            'http://web.jemberkab.go.id/' => Http::response('', 301, ['Location' => self::HOME]),
        ]);
        self::fakeNuclei([self::missingHeader('x-frame-options'), self::missingHeader('referrer-policy'), self::missingHeader('x-content-type-options')]);

        $target = $this->scan(mode: ScanMode::Quick);

        // Template Nuclei hanya melihat header, kriteria 23.1 juga menghitung frame-ancestors dan tag meta
        $keys = $target->findings->pluck('finding_key')->all();
        $this->assertNotContains('missing-x-frame-options', $keys);
        $this->assertNotContains('missing-referrer-policy', $keys);
        $this->assertNotContains('missing-x-content-type-options', $keys);
        $this->assertCount(0, $target->riskItems);

        $nuclei = $target->observations->firstWhere('check_key', 'nuclei');
        $this->assertStringContainsString('pemeriksaan bawaan menemukan kontrolnya', $nuclei->raw['ignored_keys']['missing-x-frame-options']);
        $this->assertStringContainsString('diabaikan karena pemeriksaan bawaan', $nuclei->summary);
        // Nuclei tetap tercatat menilai kunci itu
        $this->assertContains('Nuclei', $this->coverage($target)['missing-x-frame-options']['assessors']);
    }

    public function test_temuan_header_nuclei_tetap_dipakai_jika_pemeriksaan_bawaan_juga_fail(): void
    {
        $headers = self::secureHeaders();
        unset($headers['Content-Security-Policy']);
        FakeNetwork::http([
            self::HOME => Http::response('<title>Dinas</title>', 200, $headers),
            'http://web.jemberkab.go.id/' => Http::response('', 301, ['Location' => self::HOME]),
        ]);
        self::fakeNuclei([self::missingHeader('content-security-policy')]);

        $target = $this->scan(mode: ScanMode::Quick);

        $this->assertSame(['internal', 'nuclei'], $target->findings->firstWhere('finding_key', 'missing-csp')->sources);
    }

    public function test_redirect_yang_tidak_diikuti_membuat_hasil_header_nuclei_diabaikan(): void
    {
        FakeNetwork::http([
            self::HOME => Http::response('', 302, ['Location' => 'https://portal.jemberkab.go.id/']),
            'http://web.jemberkab.go.id/' => Http::response('', 301, ['Location' => self::HOME]),
        ]);
        self::fakeNuclei([self::missingHeader('x-frame-options')]);

        $target = $this->scan(mode: ScanMode::Quick);
        $coverage = $this->coverage($target);

        $this->assertNull($target->findings->firstWhere('finding_key', 'missing-x-frame-options'));
        $this->assertSame(ObservationStatus::NotAssessed, $coverage['missing-x-frame-options']['status']);
        $this->assertSame(ObservationStatus::NotAssessed, $coverage['insecure-cookie']['status']);
    }

    public function test_website_tanpa_https_membuat_kunci_https_tidak_berlaku(): void
    {
        FakeNetwork::http([
            self::HOME => 'refused',
            'http://web.jemberkab.go.id/' => Http::response('<title>Tanpa HTTPS</title>', 200),
        ]);
        // Nuclei memindai http://, hasil cookie tanpa Secure di HTTP tidak dinilai sebagai insecure-cookie (bagian 23.1)
        self::fakeNuclei([[
            'template-id' => 'cookies-without-secure', 'info' => ['name' => 'Cookies without Secure attribute', 'severity' => 'info', 'tags' => ['misconfig']],
            'matched-at' => 'http://web.jemberkab.go.id/', 'extracted-results' => ['PHPSESSID=abc'],
        ]]);

        $target = $this->scan();
        $coverage = $this->coverage($target);

        $this->assertSame(ObservationStatus::Fail, $coverage['no-https']['status']);
        $this->assertNull($target->findings->firstWhere('finding_key', 'insecure-cookie'));

        foreach (config('siprika_scanner.https_keys') as $key) {
            $this->assertSame(ObservationStatus::NotApplicable, $coverage[$key]['status'], $key);
        }

        $this->assertStringContainsString('no-https', $coverage['tls-weak-cipher']['note']);
        $this->assertNotContains('tls-weak-cipher', $target->observations->firstWhere('check_key', 'nuclei')->raw['assessed_keys']);
    }

    public function test_pemeriksaan_yang_gagal_membuat_kuncinya_error_bukan_not_assessed(): void
    {
        $this->fakeSecureSite();
        $this->app->instance(SecurityHeadersCheck::class, new class extends SecurityHeadersCheck
        {
            public function run(ScanContext $context): void
            {
                throw new RuntimeException('parser rusak');
            }
        });

        $coverage = $this->coverage($this->scan(mode: ScanMode::Quick));

        foreach (['missing-hsts', 'missing-csp', 'missing-referrer-policy', 'server-version-disclosure'] as $key) {
            $this->assertSame(ObservationStatus::Error, $coverage[$key]['status'], $key);
        }

        $this->assertStringContainsString('parser rusak', $coverage['missing-csp']['note']);
        // Kunci dari pemeriksaan lain tidak terpengaruh
        $this->assertSame(ObservationStatus::Pass, $coverage['insecure-cookie']['status']);
    }

    public function test_finding_membuat_kunci_fail_dengan_sumbernya(): void
    {
        FakeNetwork::http([
            self::HOME => Http::response('<title>Dinas</title>', 200, ['Server' => 'Apache/2.4.41']),
            'http://web.jemberkab.go.id/' => Http::response('', 301, ['Location' => self::HOME]),
        ]);

        $coverage = $this->coverage($this->scan(mode: ScanMode::Quick));

        $this->assertSame(ObservationStatus::Fail, $coverage['server-version-disclosure']['status']);
        $this->assertSame('Ditemukan oleh: Pemeriksaan bawaan.', $coverage['server-version-disclosure']['note']);
    }
}
