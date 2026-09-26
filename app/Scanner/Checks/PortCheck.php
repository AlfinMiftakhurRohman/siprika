<?php

namespace App\Scanner\Checks;

use App\Enums\ObservationStatus;
use App\Scanner\Network\PortProber;
use App\Scanner\Parsers\NmapParser;
use App\Scanner\ScanContext;
use App\Scanner\Tools\ToolRunner;

/**
 * Deteksi port web yang terbuka. Nmap dipakai jika tersedia untuk identifikasi service,
 * selain itu cukup cek koneksi TCP.
 */
class PortCheck implements Check
{
    public function __construct(private PortProber $prober, private ToolRunner $tools) {}

    public function key(): string
    {
        return 'ports';
    }

    public function label(): string
    {
        return 'Port/Web Service Detection';
    }

    public function run(ScanContext $context): void
    {
        $ip = (string) $context->primaryIp();
        $ports = config('siprika.scan.web_ports', []);

        if ($this->tools->command('nmap') !== null && $this->runNmap($context, $ip, $ports)) {
            return;
        }

        $open = [];

        foreach ($ports as $port) {
            if ($this->prober->isOpen($ip, (int) $port, (float) config('siprika.scan.port_timeout'))) {
                $open[] = (int) $port;
            }
        }

        $context->overview['open_ports'] = array_map(fn ($port) => ['port' => $port, 'service' => null], $open);

        $context->observe('ports', 'Port Web', 'internal', ObservationStatus::Info,
            ($open === [] ? 'Tidak ada port web yang terbuka' : 'Port terbuka: '.implode(', ', $open)).' (dari '.count($ports).' port web yang dicek).',
            ['ip' => $ip, 'checked' => $ports, 'open' => $open]);

        if ($this->tools->command('nmap') === null) {
            $context->observe('service-version', 'Identifikasi Service', 'nmap', ObservationStatus::NotAssessed, 'Nmap belum dipasang (NMAP_PATH kosong), versi service tidak diidentifikasi.');
        }
    }

    /**
     * @param  list<int>  $ports
     */
    private function runNmap(ScanContext $context, string $ip, array $ports): bool
    {
        $timeout = min((int) config('siprika.tools.nmap.timeout'), $context->remainingSeconds());
        $result = $this->tools->run('nmap', ['-Pn', '-sV', '--version-light', '-p', implode(',', $ports), '-oX', '-', $ip], $timeout);

        $services = $result->successful ? NmapParser::parse($result->output) : null;

        if ($services === null) {
            $context->observe('service-version', 'Identifikasi Service', 'nmap', ObservationStatus::Error, $result->successful ? 'Output Nmap tidak dapat dibaca.' : $result->errorSummary());

            return false;
        }

        $context->overview['open_ports'] = $services;
        $summary = $services === []
            ? 'Tidak ada port web yang terbuka.'
            : implode('; ', array_map(fn ($s) => "{$s['port']}/{$s['service']}".($s['product'] ? " ({$s['product']}".($s['version'] ? " {$s['version']}" : '').')' : ''), $services)).'.';

        $context->observe('ports', 'Port Web', 'nmap', ObservationStatus::Info, $summary, ['ip' => $ip, 'checked' => $ports, 'services' => $services]);
        $context->observe('service-version', 'Identifikasi Service', 'nmap', ObservationStatus::Info, $summary, ['services' => $services]);

        return true;
    }
}
