<?php

namespace App\Scanner\Checks;

use App\Enums\ObservationStatus;
use App\Scanner\Network\DnsResolver;
use App\Scanner\Network\IpGuard;
use App\Scanner\ScanContext;
use App\Support\TargetUrlNormalizer;
use InvalidArgumentException;
use RuntimeException;

/**
 * Validasi URL, DNS, dan perlindungan SSRF sebelum permintaan apa pun dikirim ke target.
 */
class TargetValidationCheck implements Check
{
    public function __construct(private DnsResolver $dns) {}

    public function key(): string
    {
        return 'target-validation';
    }

    public function label(): string
    {
        return 'Validasi Target';
    }

    public function run(ScanContext $context): void
    {
        // Daftar domain bisa berubah sejak URL dimasukkan, jadi dicek ulang
        try {
            TargetUrlNormalizer::fromConfig()->normalize($context->url());
        } catch (InvalidArgumentException $e) {
            $this->fail($context, ObservationStatus::Fail, 'URL ditolak: '.$e->getMessage());
        }

        try {
            $ips = $this->resolveWithRetry($context->host());
        } catch (RuntimeException $e) {
            $context->networkLost = true;
            $this->fail($context, ObservationStatus::Error, 'DNS gagal: '.$e->getMessage());
        }

        if ($ips === []) {
            $this->fail($context, ObservationStatus::Fail, "Domain {$context->host()} tidak ditemukan di DNS (tidak ada record A/AAAA). Periksa kembali penulisan domain.");
        }

        $blocked = array_values(array_filter($ips, fn (string $ip) => ! IpGuard::isPublic($ip)));

        if ($blocked !== []) {
            $this->fail(
                $context,
                ObservationStatus::Fail,
                'Domain mengarah ke alamat IP non-publik ('.implode(', ', $blocked).'), pemeriksaan dihentikan untuk mencegah SSRF.',
                ['ips' => $ips, 'blocked' => $blocked],
            );
        }

        $context->ips = $ips;
        $context->http->pin($context->host(), $ips);
        $context->overview['ip_addresses'] = $ips;

        $context->observe('dns', 'Validasi URL & DNS', 'internal', ObservationStatus::Pass, 'Domain ter-resolve ke '.implode(', ', $ips).'.', ['ips' => $ips]);
    }

    /**
     * @return list<string>
     */
    private function resolveWithRetry(string $host): array
    {
        try {
            return $this->dns->resolve($host);
        } catch (RuntimeException) {
            return $this->dns->resolve($host);
        }
    }

    /**
     * @param  array<string, mixed>|null  $raw
     */
    private function fail(ScanContext $context, ObservationStatus $status, string $message, ?array $raw = null): never
    {
        $context->observe('dns', 'Validasi URL & DNS', 'internal', $status, $message, $raw);
        $context->abort($message);
    }
}
