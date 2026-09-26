<?php

namespace App\Scanner\Checks;

use App\Enums\ObservationStatus;
use App\Scanner\Network\DnsResolver;
use App\Scanner\Network\IpGuard;
use App\Scanner\ScanContext;
use App\Scanner\Tools\ToolRunner;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Str;
use RuntimeException;

/**
 * Dasar pemeriksaan yang memakai tool eksternal opsional.
 */
abstract class ExternalToolCheck implements Check
{
    public function __construct(protected ToolRunner $tools, private DnsResolver $dns) {}

    /**
     * Nama tool di config siprika.tools.
     */
    abstract protected function tool(): string;

    /**
     * Nama variabel .env untuk pesan NOT ASSESSED.
     */
    abstract protected function envName(): string;

    abstract protected function execute(ScanContext $context): void;

    /**
     * Tool sudah diatur di .env.
     */
    public function isAvailable(): bool
    {
        return $this->tools->command($this->tool()) !== null;
    }

    public function run(ScanContext $context): void
    {
        if (! $this->isAvailable()) {
            $this->observe($context, ObservationStatus::NotAssessed, "{$this->label()} belum dipasang ({$this->envName()} kosong).");

            return;
        }

        $unsafe = $this->unsafeTargetReason($context);

        if ($unsafe !== null) {
            $this->observe($context, ObservationStatus::Error, $unsafe);

            return;
        }

        $this->execute($context);
    }

    /**
     * Tool eksternal me-resolve DNS sendiri, di luar penguncian IP SafeHttpClient. Host diperiksa ulang tepat
     * sebelum tool dijalankan, supaya domain yang berpindah ke IP privat (DNS rebinding) tidak dipindai (bagian 26).
     */
    private function unsafeTargetReason(ScanContext $context): ?string
    {
        $host = (string) (parse_url($context->reachableUrl(), PHP_URL_HOST) ?: $context->host());

        try {
            $ips = $this->dns->resolve($host);
        } catch (RuntimeException) {
            $ips = [];
        }

        if ($ips === []) {
            return "{$this->label()} tidak dijalankan: DNS {$host} tidak dapat diperiksa ulang.";
        }

        foreach ($ips as $ip) {
            if (! IpGuard::isPublic($ip)) {
                return "{$this->label()} tidak dijalankan: {$host} kini mengarah ke alamat IP non-publik ({$ip}), perlindungan SSRF.";
            }
        }

        return null;
    }

    /**
     * Catat observation pemeriksaan ini dengan kunci, label, dan nama tool-nya.
     *
     * @param  array<string, mixed>|null  $raw
     */
    protected function observe(ScanContext $context, ObservationStatus $status, string $summary, ?array $raw = null): void
    {
        $context->observe($this->key(), $this->label(), $this->tool(), $status, $summary, $raw);
    }

    protected function timeout(ScanContext $context): int
    {
        return min((int) config("siprika.tools.{$this->tool()}.timeout"), $context->remainingSeconds());
    }

    /**
     * Jalankan callback di folder kerja sementara, folder dihapus setelahnya.
     *
     * @template T
     *
     * @param  callable(string): T  $callback
     * @return T
     */
    protected function inWorkDirectory(callable $callback): mixed
    {
        $directory = storage_path('app/private/scans/'.$this->tool().'-'.Str::random(12));
        File::ensureDirectoryExists($directory);

        try {
            return $callback($directory);
        } finally {
            File::deleteDirectory($directory);
        }
    }
}
