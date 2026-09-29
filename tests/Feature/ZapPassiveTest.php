<?php

namespace Tests\Feature;

use App\Enums\ObservationStatus;
use App\Enums\ScanMode;
use App\Enums\ScanTargetStatus;
use App\Models\ScanTarget;
use App\Scanner\CatalogCoverage;
use App\Scanner\Parsers\ZapParser;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Tests\Support\FakeNetwork;
use Tests\Support\InteractsWithScanner;
use Tests\TestCase;

/**
 * OWASP ZAP passive scan lewat API daemon (bagian 4, Mode Standar).
 */
class ZapPassiveTest extends TestCase
{
    use InteractsWithScanner;
    use RefreshDatabase;

    private const HOME = 'https://web.jemberkab.go.id/';

    private const ZAP = 'http://127.0.0.1:8080';

    protected function setUp(): void
    {
        parent::setUp();

        $this->setUpScanner();
        config(['siprika.tools.zap.url' => self::ZAP, 'siprika.tools.zap.api_key' => 'kunci-uji']);
    }

    /**
     * Website dan API ZAP palsu. Alert memakai format asli ZAP 2.17 (alert/view/alerts).
     *
     * @param  list<array<string, string>>  $alerts
     * @param  array<string, string>|null  $headers  header halaman utama, bawaan semua kontrol keamanan diterapkan
     */
    private function fakeSiteAndZap(array $alerts, ?array $headers = null, int $pendingRecords = 0): void
    {
        FakeNetwork::http([
            self::HOME => Http::response('<title>Dinas</title>', 200, $headers ?? self::secureHeaders()),
            'http://web.jemberkab.go.id/' => Http::response('', 301, ['Location' => self::HOME]),
            self::ZAP.'/JSON/*' => function (Request $request) use ($alerts, &$pendingRecords) {
                return match (true) {
                    str_contains($request->url(), 'pscan/view/recordsToScan') => Http::response(['recordsToScan' => (string) max(0, $pendingRecords--)]),
                    str_contains($request->url(), 'alert/view/alerts') => Http::response(['alerts' => $alerts]),
                    str_contains($request->url(), 'core/action/accessUrl') => Http::response(['accessUrl' => [['responseHeader' => 'HTTP/1.1 200 OK']]]),
                    default => Http::response(['Result' => 'OK']),
                };
            },
        ]);
    }

    private static function alert(string $pluginId, string $alertRef, string $name, string $param = '', string $evidence = ''): array
    {
        return ['pluginId' => $pluginId, 'alertRef' => $alertRef, 'alert' => $name, 'risk' => 'Low', 'confidence' => 'Medium', 'url' => self::HOME, 'param' => $param, 'evidence' => $evidence];
    }

    private function observation(ScanTarget $target): object
    {
        return $target->observations->firstWhere('check_key', 'zap-passive');
    }

    public function test_alert_zap_dipetakan_ke_katalog_dengan_aturan_cookie_dan_versi(): void
    {
        $this->fakeSiteAndZap([
            self::alert('10010', '10010', 'Cookie No HttpOnly Flag', 'XSRF-TOKEN', 'set-cookie: XSRF-TOKEN'),
            self::alert('10010', '10010', 'Cookie No HttpOnly Flag', 'laravel_session', 'set-cookie: laravel_session'),
            self::alert('10054', '10054-1', 'Cookie without SameSite Attribute', 'pref', 'Set-Cookie: pref'),
            self::alert('10037', '10037', 'Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s)', '', 'X-Powered-By: PHP/8.3.33'),
            self::alert('10037', '10037', 'Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s)', '', 'X-Powered-By: ASP.NET'),
            self::alert('90003', '90003', 'Sub Resource Integrity Attribute Missing', '', '<script src="https://cdn.example/x.js">'),
        ]);

        $target = $this->scan();

        // Hanya cookie sesi yang tidak dibaca JavaScript wajib HttpOnly; SameSite hanya untuk cookie sesi
        $cookie = $target->findings->firstWhere('finding_key', 'insecure-cookie');
        $this->assertSame(['zap'], $cookie->sources);
        $this->assertSame(['cookie laravel_session tanpa HttpOnly (OWASP ZAP)'], $cookie->evidences->pluck('detail')->all());

        // X-Powered-By tanpa nomor versi bukan temuan
        $version = $target->findings->firstWhere('finding_key', 'server-version-disclosure');
        $this->assertStringContainsString('PHP/8.3.33', $version->evidences->firstWhere('source', 'zap')->detail);
        $this->assertCount(1, $version->evidences->where('source', 'zap'));

        // Alert di luar katalog hanya informasi
        $this->assertNull($target->findings->first(fn ($f) => str_contains($f->finding_key, '90003')));
        $observation = $this->observation($target);
        $this->assertSame(ObservationStatus::Fail, $observation->status);
        $this->assertStringContainsString('Sub Resource Integrity Attribute Missing', $observation->summary);
        $this->assertSame('zap', $observation->tool);
    }

    public function test_zap_dipanggil_tanpa_mengikuti_redirect_dan_dengan_user_agent_siprika(): void
    {
        $this->fakeSiteAndZap([], pendingRecords: 2);

        $target = $this->scan();

        $zapCalls = collect(Http::recorded())->map(fn ($pair) => $pair[0])->filter(fn (Request $r) => str_starts_with($r->url(), self::ZAP));
        $paths = $zapCalls->map(fn (Request $r) => parse_url($r->url(), PHP_URL_PATH))->values()->all();

        $this->assertSame('/JSON/core/action/newSession/', $paths[0]);
        $this->assertContains('/JSON/network/action/setDefaultUserAgent/', $paths);
        $this->assertTrue($zapCalls->every(fn (Request $r) => $r['apikey'] === 'kunci-uji'));

        $access = $zapCalls->first(fn (Request $r) => str_contains($r->url(), 'accessUrl'));
        $this->assertSame($target->overview['final_url'], $access['url']);
        $this->assertSame('false', $access['followRedirects']);
        $this->assertSame(config('siprika.scan.user_agent'), $zapCalls->first(fn (Request $r) => str_contains($r->url(), 'setDefaultUserAgent'))['userAgent']);

        // Menunggu passive scan selesai sebelum membaca alert
        $this->assertGreaterThanOrEqual(3, $zapCalls->filter(fn (Request $r) => str_contains($r->url(), 'recordsToScan'))->count());
        $this->assertSame(ObservationStatus::Pass, $this->observation($target)->status);
    }

    public function test_kolom_kerawanan_tidak_mengulang_temuan_yang_sama_dari_zap(): void
    {
        $headers = self::secureHeaders();
        unset($headers['Strict-Transport-Security']);
        $this->fakeSiteAndZap([self::alert('10035', '10035-1', 'Strict-Transport-Security Header Not Set')], $headers);

        $target = $this->scan();

        $this->assertSame(['internal', 'zap'], $target->findings->firstWhere('finding_key', 'missing-hsts')->sources);
        // Endpoint sama: cukup penjelasan pemeriksaan bawaan
        $this->assertSame(
            'Lemahnya mekanisme kriptografi aplikasi (header Strict-Transport-Security tidak ditemukan pada respons HTTPS)',
            $target->riskItems->firstWhere('finding_key', 'missing-hsts')->vulnerability,
        );
    }

    public function test_kunci_yang_dinilai_zap_masuk_coverage(): void
    {
        $this->fakeSiteAndZap([]);

        $target = $this->scan();
        $coverage = collect(CatalogCoverage::for($target))->keyBy('key');

        $this->assertContains('OWASP ZAP Passive', $coverage['insecure-cookie']['assessors']);
        $this->assertContains('OWASP ZAP Passive', $coverage['missing-csp']['assessors']);
        $this->assertNotContains('OWASP ZAP Passive', $coverage['tls-weak-cipher']['assessors']);
    }

    public function test_temuan_header_zap_dibuang_jika_pemeriksaan_bawaan_pass(): void
    {
        // Pemeriksaan bawaan: frame-ancestors di CSP sudah melindungi dari clickjacking walaupun X-Frame-Options tidak ada
        $headers = self::secureHeaders();
        unset($headers['X-Frame-Options']);
        $this->fakeSiteAndZap([self::alert('10020', '10020-1', 'Missing Anti-clickjacking Header', 'x-frame-options')], $headers);

        $target = $this->scan();

        $this->assertNull($target->findings->firstWhere('finding_key', 'missing-x-frame-options'));
        $this->assertArrayHasKey('missing-x-frame-options', $this->observation($target)->raw['ignored_keys']);
    }

    public function test_zap_mati_dicatat_error_dan_scan_tetap_selesai(): void
    {
        FakeNetwork::http([
            self::HOME => Http::response('<title>Dinas</title>', 200, self::secureHeaders()),
            'http://web.jemberkab.go.id/' => Http::response('', 301, ['Location' => self::HOME]),
            self::ZAP.'/JSON/*' => 'refused',
        ]);

        $target = $this->scan();

        $this->assertSame(ScanTargetStatus::Partial, $target->status);
        $this->assertSame(ObservationStatus::Error, $this->observation($target)->status);
        $this->assertStringContainsString('ZAP tidak dapat dihubungi', $this->observation($target)->summary);
    }

    public function test_zap_tidak_dijalankan_tanpa_zap_url_atau_di_mode_cepat(): void
    {
        config(['siprika.tools.zap.url' => null]);
        $this->fakeSiteAndZap([]);

        $standard = $this->scan();
        $this->assertSame(ObservationStatus::NotAssessed, $this->observation($standard)->status);
        $this->assertStringContainsString('ZAP_URL kosong', $this->observation($standard)->summary);

        config(['siprika.tools.zap.url' => self::ZAP]);
        $quick = $this->scan(mode: ScanMode::Quick);
        $this->assertSame(ObservationStatus::NotAssessed, $this->observation($quick)->status);
        Http::assertNotSent(fn (Request $r) => str_starts_with($r->url(), self::ZAP));
    }

    public function test_parser_alert_zap(): void
    {
        $parsed = ZapParser::parse([
            self::alert('10035', '10035-1', 'Strict-Transport-Security Header Not Set'),
            self::alert('10011', '10011', 'Cookie Without Secure Flag', 'pref', 'Set-Cookie: pref'),
            self::alert('10054', '10054-2', 'Cookie with SameSite Attribute None', 'PHPSESSID', 'Set-Cookie: PHPSESSID'),
            self::alert('10036', '10036-1', 'Server Header', '', 'nginx'),
            self::alert('10015', '10015', 'Re-examine Cache-control Directives', 'cache-control', 'no-cache'),
        ]);

        // SameSite=None tetap memiliki atribut SameSite, header Server tanpa versi bukan temuan
        $this->assertSame(['missing-hsts', 'insecure-cookie'], array_map(fn ($f) => $f->key, $parsed['findings']));
        $this->assertSame('cookie pref tanpa Secure (OWASP ZAP)', $parsed['findings'][1]->detail);
        $this->assertCount(5, $parsed['alerts']);
    }
}
