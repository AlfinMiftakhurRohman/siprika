<?php

namespace Tests\Feature;

use App\Enums\ScanMode;
use App\Http\Middleware\ProtectLocalApp;
use App\Models\ScanBatch;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Queue;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

/**
 * SIPRIKA tanpa login dilindungi dari website lain yang dibuka di browser yang sama.
 */
class LocalAppProtectionTest extends TestCase
{
    use RefreshDatabase;

    /**
     * @return array<string, array{string, bool}>
     */
    public static function hostProvider(): array
    {
        return [
            'ip lokal' => ['127.0.0.1', true],
            'localhost' => ['localhost', true],
            'localhost huruf besar' => ['LOCALHOST', true],
            'subdomain localhost' => ['siprika.localhost', true],
            'ipv6 lokal' => ['[::1]', true],
            'ip jaringan' => ['192.168.1.10', true],
            'domain penyerang' => ['evil.example', false],
            'domain berawalan localhost' => ['localhost.evil.example', false],
            'domain yang mengarah ke 127.0.0.1' => ['127.0.0.1.nip.io', false],
            'kosong' => ['', false],
        ];
    }

    #[DataProvider('hostProvider')]
    public function test_hanya_alamat_ip_localhost_dan_host_app_url_yang_diterima(string $host, bool $trusted): void
    {
        $this->assertSame($trusted, ProtectLocalApp::isTrustedHost($host));
    }

    public function test_website_lain_tidak_dapat_membaca_hasil_atau_memulai_pemeriksaan_lewat_dns_rebinding(): void
    {
        Queue::fake();
        $batch = ScanBatch::create(['mode' => ScanMode::Quick]);

        // Domain penyerang yang diarahkan ke 127.0.0.1: browser menganggapnya satu origin dengan halaman penyerang
        $this->get("http://evil.example:8000/scans/{$batch->id}")->assertStatus(400);
        $this->get("http://evil.example:8000/scans/{$batch->id}/export")->assertStatus(400);
        $this->getJson("http://evil.example:8000/scans/{$batch->id}/progress")->assertStatus(400);
        $this->post('http://evil.example:8000/scans', ['urls' => 'e-sakip.jemberkab.go.id', 'mode' => 'quick'], ['Sec-Fetch-Site' => 'same-origin'])
            ->assertStatus(400);

        $this->assertSame(1, ScanBatch::count());
        Queue::assertNothingPushed();

        $this->get("http://127.0.0.1:8000/scans/{$batch->id}")->assertOk();
        $this->get("http://localhost:8000/scans/{$batch->id}")->assertOk();
    }

    public function test_host_dari_app_url_diterima(): void
    {
        config(['app.url' => 'http://siprika.test']);

        $this->get('http://siprika.test/')->assertOk();
    }

    public function test_halaman_tidak_dapat_dibingkai_website_lain(): void
    {
        $this->get(route('scans.create'))
            ->assertOk()
            ->assertHeader('X-Frame-Options', 'DENY')
            ->assertHeader('Content-Security-Policy', "frame-ancestors 'none'")
            ->assertHeader('X-Content-Type-Options', 'nosniff')
            ->assertHeader('Referrer-Policy', 'same-origin');
    }
}
