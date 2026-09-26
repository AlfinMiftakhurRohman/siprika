<?php

namespace App\Scanner;

use App\Enums\ObservationStatus;
use App\Enums\ScanMode;
use App\Models\ScanTarget;
use App\Scanner\Data\FindingData;
use App\Scanner\Data\ObservationData;
use App\Scanner\Network\HttpExchange;
use App\Scanner\Network\HttpFailure;
use App\Scanner\Network\SafeHttpClient;
use App\Scanner\Network\TlsReport;

/**
 * Data bersama selama pemeriksaan satu website.
 */
class ScanContext
{
    /** @var list<string> IP hasil resolve yang sudah divalidasi */
    public array $ips = [];

    /** Respons halaman utama setelah mengikuti redirect */
    public ?HttpExchange $homepage = null;

    public ?HttpExchange $httpsResponse = null;

    public ?HttpFailure $httpsFailure = null;

    public bool $httpsAvailable = false;

    /** Respons halaman utama berupa halaman blokir WAF/CDN (bagian 22.4) */
    public bool $wafBlocked = false;

    public ?TlsReport $tlsReport = null;

    /** @var array<string, mixed> ringkasan untuk tab Overview */
    public array $overview = [];

    /** @var list<ObservationData> */
    public array $observations = [];

    /** @var list<FindingData> */
    public array $findings = [];

    public function __construct(
        public readonly ScanTarget $target,
        public readonly SafeHttpClient $http,
        public readonly float $deadline,
        public readonly ScanMode $mode = ScanMode::Standard,
    ) {}

    public function isQuick(): bool
    {
        return $this->mode === ScanMode::Quick;
    }

    public function url(): string
    {
        return $this->target->url;
    }

    public function host(): string
    {
        return $this->target->host;
    }

    /**
     * Port HTTPS target: port pada URL https (contoh https://web.id:8443), selain itu 443.
     */
    public function httpsPort(): int
    {
        $parts = parse_url($this->url());

        return ($parts['scheme'] ?? '') === 'https' && isset($parts['port']) ? (int) $parts['port'] : 443;
    }

    /**
     * Endpoint HTTPS untuk evidence, contoh https://web.id/ atau https://web.id:8443/.
     */
    public function httpsEndpoint(): string
    {
        $port = $this->httpsPort();

        return "https://{$this->host()}".($port !== 443 ? ":{$port}" : '').'/';
    }

    public function primaryIp(): ?string
    {
        return $this->ips === [] ? null : SafeHttpClient::preferIpv4($this->ips);
    }

    public function remainingSeconds(): int
    {
        return max(0, (int) floor($this->deadline - microtime(true)));
    }

    /**
     * @param  array<string, mixed>|null  $raw
     */
    public function observe(string $key, string $label, string $tool, ObservationStatus $status, ?string $summary = null, ?array $raw = null): void
    {
        $this->observations[] = new ObservationData($key, $label, $tool, $status, $summary, $raw);
    }

    public function addFinding(FindingData $finding): void
    {
        $this->findings[] = $finding;
    }

    /**
     * Gabungkan teknologi dari beberapa sumber ke overview tanpa duplikat nama. Entri dengan versi diutamakan.
     *
     * @param  list<array{name: string, category: string, version: string|null, source: string}>  $technologies
     */
    public function addTechnologies(array $technologies): void
    {
        $merged = [];

        foreach ([...($this->overview['technologies'] ?? []), ...$technologies] as $technology) {
            $key = strtolower($technology['name']);

            if (! isset($merged[$key]) || ($merged[$key]['version'] === null && $technology['version'] !== null)) {
                $merged[$key] = $technology;
            }
        }

        $cms = array_values(array_filter($merged, fn (array $technology) => $technology['category'] === 'CMS'));

        $this->overview['technologies'] = array_values($merged);
        $this->overview['cms'] = $cms === [] ? null : Fingerprint::describe([$cms[0]]);
    }

    public function abort(string $message): never
    {
        throw new TargetAborted($message);
    }

    /**
     * URL halaman utama yang benar-benar dapat diakses (setelah redirect), atau URL target jika tidak ada.
     * Contoh: input tanpa skema dianggap https://, tetapi website hanya melayani http://.
     */
    public function reachableUrl(): string
    {
        return $this->homepage !== null && $this->homepage->stoppedReason === null ? $this->homepage->url : $this->url();
    }

    /**
     * Asal (scheme://host[:port]) dari URL yang dapat diakses.
     */
    public function origin(): string
    {
        $parts = parse_url($this->reachableUrl());

        return $parts['scheme'].'://'.$parts['host'].(isset($parts['port']) ? ':'.$parts['port'] : '');
    }
}
