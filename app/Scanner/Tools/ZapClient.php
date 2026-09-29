<?php

namespace App\Scanner\Tools;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;
use RuntimeException;

/**
 * Klien API OWASP ZAP daemon untuk passive scan (bagian 4). ZAP hanya mengambil halaman lalu
 * menganalisis respons secara pasif, tanpa active scan, spider, atau mengikuti redirect.
 */
class ZapClient
{
    public function isConfigured(): bool
    {
        return trim((string) config('siprika.tools.zap.url')) !== '';
    }

    /**
     * Ambil satu halaman lewat ZAP, tunggu passive scan selesai, lalu kembalikan alert untuk asal URL tersebut.
     *
     * @return list<array<string, mixed>>
     *
     * @throws RuntimeException jika ZAP gagal atau melewati batas waktu
     */
    public function passiveScan(string $url, int $timeout): array
    {
        $deadline = microtime(true) + $timeout;

        // Sesi baru supaya alert website sebelumnya tidak ikut terbaca; website diperiksa satu per satu
        $this->call('core/action/newSession', ['overwrite' => 'true'], $timeout);
        // User-Agent tetap supaya admin website dapat mengenali pemeriksaan (bagian 22.9)
        $this->call('network/action/setDefaultUserAgent', ['userAgent' => (string) config('siprika.scan.user_agent')], $timeout);
        $this->call('core/action/accessUrl', ['url' => $url, 'followRedirects' => 'false'], max(1, (int) ($deadline - microtime(true))));

        while ((int) ($this->call('pscan/view/recordsToScan', [], 10)['recordsToScan'] ?? 0) > 0) {
            if (microtime(true) >= $deadline) {
                throw new RuntimeException("Passive scan ZAP melewati batas waktu ({$timeout} detik).");
            }

            usleep(500_000);
        }

        $parts = parse_url($url);
        $origin = $parts['scheme'].'://'.$parts['host'].(isset($parts['port']) ? ':'.$parts['port'] : '');

        return array_values($this->call('alert/view/alerts', ['baseurl' => $origin, 'start' => '0', 'count' => '500'], 30)['alerts'] ?? []);
    }

    /**
     * @param  array<string, string>  $parameters
     * @return array<string, mixed>
     */
    private function call(string $endpoint, array $parameters, int $timeout): array
    {
        $url = rtrim((string) config('siprika.tools.zap.url'), '/')."/JSON/{$endpoint}/";

        try {
            $response = Http::timeout($timeout)->acceptJson()->get($url, $parameters + ['apikey' => (string) config('siprika.tools.zap.api_key')]);
        } catch (ConnectionException $e) {
            throw new RuntimeException('ZAP tidak dapat dihubungi di '.config('siprika.tools.zap.url').': '.mb_substr($e->getMessage(), 0, 200));
        }

        if (! $response->successful() || ! is_array($response->json())) {
            $message = $response->json('message') ?? $response->json('code') ?? mb_substr($response->body(), 0, 200);

            throw new RuntimeException("API ZAP {$endpoint} gagal (status {$response->status()}): {$message}");
        }

        return $response->json();
    }
}
