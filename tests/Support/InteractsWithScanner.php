<?php

namespace Tests\Support;

use App\Enums\ScanMode;
use App\Jobs\ProcessScanTarget;
use App\Models\ScanBatch;
use App\Models\ScanTarget;
use App\Scanner\Network\DnsResolver;
use App\Scanner\Network\PortProber;
use App\Scanner\Network\TlsInspector;
use Illuminate\Process\PendingProcess;

trait InteractsWithScanner
{
    protected FakeNetwork $network;

    protected function setUpScanner(): void
    {
        $this->network = new FakeNetwork;

        $this->app->instance(DnsResolver::class, $this->network);
        $this->app->instance(TlsInspector::class, $this->network);
        $this->app->instance(PortProber::class, $this->network);

        config([
            'siprika.allowed_domains' => ['jemberkab.go.id'],
            'siprika.scan.request_delay_ms' => 0,
            'siprika.tools.nuclei.command' => null,
            'siprika.tools.testssl.command' => null,
            'siprika.tools.whatweb.command' => null,
            'siprika.tools.nmap.command' => null,
            'siprika.ai.enabled' => false,
        ]);
    }

    protected function scan(string $url = 'https://web.jemberkab.go.id', ?ScanBatch $batch = null, ScanMode $mode = ScanMode::Standard): ScanTarget
    {
        $batch ??= ScanBatch::create(['mode' => $mode]);
        $target = $batch->targets()->create([
            'position' => $batch->targets()->count() + 1,
            'url' => $url,
            'host' => parse_url($url, PHP_URL_HOST),
        ]);

        ProcessScanTarget::dispatchSync($target);

        return $target->fresh();
    }

    /**
     * Perintah proses sebagai satu string, untuk assertion Process::assertRan.
     */
    protected static function commandOf(PendingProcess $process): string
    {
        return is_array($process->command) ? implode(' ', $process->command) : (string) $process->command;
    }

    /**
     * Halaman yang menerapkan semua kontrol keamanan yang diperiksa.
     *
     * @return array<string, string>
     */
    protected static function secureHeaders(): array
    {
        return [
            'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains',
            'Content-Security-Policy' => "default-src 'self'; frame-ancestors 'self'",
            'X-Frame-Options' => 'SAMEORIGIN',
            'X-Content-Type-Options' => 'nosniff',
            'Referrer-Policy' => 'strict-origin-when-cross-origin',
            'Server' => 'nginx',
            'Set-Cookie' => 'laravel_session=abc; path=/; secure; httponly; samesite=lax',
        ];
    }
}
