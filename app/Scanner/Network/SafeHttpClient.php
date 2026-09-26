<?php

namespace App\Scanner\Network;

use App\Support\TargetUrlNormalizer;
use GuzzleHttp\Exception\ResponseException;
use GuzzleHttp\Exception\TransferException;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;
use InvalidArgumentException;
use Psr\Http\Message\StreamInterface;

/**
 * HTTP client untuk pemindaian:
 * - koneksi dipaksa ke IP yang sudah dicek publik (CURLOPT_RESOLVE), mencegah DNS rebinding;
 * - redirect diikuti manual maksimal 5 langkah dan hanya ke domain yang diizinkan;
 * - kegagalan jaringan diulang satu kali (bagian 22.3);
 * - sertifikat tidak diverifikasi di sini karena TLS diperiksa terpisah oleh TlsInspector.
 */
class SafeHttpClient
{
    /**
     * IP yang sudah divalidasi per host.
     *
     * @var array<string, list<string>>
     */
    private array $pins = [];

    public function __construct(private DnsResolver $dns) {}

    /**
     * @param  list<string>  $ips
     */
    public function pin(string $host, array $ips): void
    {
        $this->pins[strtolower($host)] = array_values($ips);
    }

    /**
     * @throws HttpFailure
     */
    public function get(string $url, bool $followRedirects = true, ?int $maxBytes = null): HttpExchange
    {
        $maxBytes ??= (int) config('siprika.scan.max_body_bytes');
        $maxRedirects = $followRedirects ? (int) config('siprika.scan.max_redirects') : 0;
        $chain = [];

        while (true) {
            $exchange = $this->requestWithRetry($url, $maxBytes);

            if (! $exchange->isRedirect() || count($chain) >= $maxRedirects) {
                return $this->withChain($exchange, $chain);
            }

            $next = self::resolveUrl($url, (string) $exchange->header('location'));
            $reason = $this->redirectBlockReason($next);

            if ($reason !== null) {
                return $this->withChain($exchange, $chain, $reason);
            }

            $chain[] = $exchange;
            $url = $next;
        }
    }

    /**
     * Alasan redirect tidak diikuti, atau null jika boleh diikuti.
     */
    private function redirectBlockReason(string $url): ?string
    {
        try {
            TargetUrlNormalizer::fromConfig()->normalize($url);
        } catch (InvalidArgumentException $e) {
            return "Redirect ke {$url} tidak diikuti: {$e->getMessage()}";
        }

        return null;
    }

    /**
     * @param  list<HttpExchange>  $chain
     */
    private function withChain(HttpExchange $exchange, array $chain, ?string $stoppedReason = null): HttpExchange
    {
        return new HttpExchange($exchange->url, $exchange->status, $exchange->headers, $exchange->body, $chain, $stoppedReason);
    }

    private function requestWithRetry(string $url, int $maxBytes): HttpExchange
    {
        try {
            return $this->request($url, $maxBytes);
        } catch (HttpFailure $e) {
            if ($e->kind === HttpFailure::BLOCKED) {
                throw $e;
            }

            return $this->request($url, $maxBytes);
        }
    }

    private function request(string $url, int $maxBytes): HttpExchange
    {
        $parts = parse_url($url);
        $host = strtolower($parts['host'] ?? '');
        $scheme = strtolower($parts['scheme'] ?? 'http');
        $port = $parts['port'] ?? ($scheme === 'https' ? 443 : 80);

        $ip = $this->pinnedIp($host);
        $resolveEntry = str_contains($ip, ':') ? "{$host}:{$port}:[{$ip}]" : "{$host}:{$port}:{$ip}";

        $limitReached = false;

        try {
            // Tanpa opsi stream supaya Guzzle memakai handler cURL (CURLOPT_RESOLVE hanya didukung cURL).
            // Unduhan dihentikan setelah batas ukuran, supaya file besar (contoh log 300 MB) tidak dibaca utuh.
            // Accept-Encoding identity: jumlah byte yang dihitung sama dengan isi yang dibaca.
            $response = Http::withOptions([
                'allow_redirects' => false,
                'verify' => false,
                'http_errors' => false,
                'curl' => [CURLOPT_RESOLVE => [$resolveEntry]],
                'progress' => function (int $downloadTotal, int $downloaded) use ($maxBytes, &$limitReached): bool {
                    return $limitReached = $downloaded > $maxBytes;
                },
            ])
                ->withHeaders(['Accept-Encoding' => 'identity'])
                ->withUserAgent((string) config('siprika.scan.user_agent'))
                ->timeout((int) config('siprika.scan.http_timeout'))
                ->connectTimeout((int) config('siprika.scan.connect_timeout'))
                ->get($url)
                ->toPsrResponse();
        } catch (ConnectionException|TransferException $e) {
            // Transfer yang sengaja dihentikan karena batas ukuran tetap memakai header dan isi yang sudah diterima.
            // Laravel membungkus ResponseException Guzzle di dalam ConnectionException.
            $partial = $e instanceof ResponseException ? $e : $e->getPrevious();

            if (! $limitReached || ! $partial instanceof ResponseException) {
                throw HttpFailure::fromMessage($e->getMessage());
            }

            $response = $partial->getResponse();
        }

        $headers = [];

        foreach ($response->getHeaders() as $name => $values) {
            $headers[strtolower($name)] = array_merge($headers[strtolower($name)] ?? [], array_values($values));
        }

        return new HttpExchange($url, $response->getStatusCode(), $headers, self::readBody($response->getBody(), $maxBytes));
    }

    /**
     * Baca isi respons maksimal $maxBytes tanpa memuat sisanya ke memori.
     */
    private static function readBody(StreamInterface $stream, int $maxBytes): string
    {
        if ($stream->isSeekable()) {
            $stream->rewind();
        }

        $body = '';

        while (! $stream->eof() && strlen($body) < $maxBytes) {
            $chunk = $stream->read(min(65536, $maxBytes - strlen($body)));

            if ($chunk === '') {
                break;
            }

            $body .= $chunk;
        }

        return $body;
    }

    /**
     * IP untuk host: memakai IP yang sudah di-pin, atau resolve lalu validasi.
     */
    private function pinnedIp(string $host): string
    {
        if (! isset($this->pins[$host])) {
            try {
                $ips = $this->dns->resolve($host);
            } catch (\RuntimeException $e) {
                throw new HttpFailure(HttpFailure::DNS, $e->getMessage());
            }

            if ($ips === []) {
                throw new HttpFailure(HttpFailure::DNS, "Domain {$host} tidak dapat di-resolve.");
            }

            foreach ($ips as $ip) {
                if (! IpGuard::isPublic($ip)) {
                    throw new HttpFailure(HttpFailure::BLOCKED, "Host {$host} mengarah ke alamat IP non-publik ({$ip}).");
                }
            }

            $this->pins[$host] = $ips;
        }

        return self::preferIpv4($this->pins[$host]);
    }

    /**
     * @param  list<string>  $ips
     */
    public static function preferIpv4(array $ips): string
    {
        foreach ($ips as $ip) {
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                return $ip;
            }
        }

        return $ips[0];
    }

    /**
     * Menggabungkan URL dasar dengan nilai header Location.
     */
    public static function resolveUrl(string $base, string $location): string
    {
        $location = trim($location);

        if (preg_match('~^[a-z][a-z0-9+.\-]*://~i', $location)) {
            return $location;
        }

        $parts = parse_url($base);
        $origin = $parts['scheme'].'://'.$parts['host'].(isset($parts['port']) ? ':'.$parts['port'] : '');

        if (str_starts_with($location, '//')) {
            return $parts['scheme'].':'.$location;
        }

        if (str_starts_with($location, '/')) {
            return $origin.$location;
        }

        $path = $parts['path'] ?? '/';
        $dir = substr($path, 0, (int) strrpos($path, '/') + 1);

        if (str_starts_with($location, '?')) {
            return $origin.$path.$location;
        }

        return $origin.($dir === '' ? '/' : $dir).$location;
    }
}
