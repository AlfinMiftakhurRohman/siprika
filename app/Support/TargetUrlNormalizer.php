<?php

namespace App\Support;

use InvalidArgumentException;

/**
 * Normalisasi dan validasi satu URL target sebelum masuk antrean.
 * Validasi DNS dan pengecekan IP hasil resolve dikerjakan di tahap scanner.
 */
class TargetUrlNormalizer
{
    public const MAX_LENGTH = 2048;

    /**
     * @param  list<string>  $allowedDomains  daftar kosong atau berisi "*" berarti semua domain diizinkan
     */
    public function __construct(private array $allowedDomains) {}

    /**
     * Normalizer dengan daftar domain dari SCAN_ALLOWED_DOMAINS.
     */
    public static function fromConfig(): self
    {
        return new self(config('siprika.allowed_domains', []));
    }

    public function allowsAllDomains(): bool
    {
        return $this->allowedDomains === [] || in_array('*', $this->allowedDomains, true);
    }

    /**
     * @return array{url: string, host: string}
     *
     * @throws InvalidArgumentException jika URL ditolak, pesan berisi alasannya
     */
    public function normalize(string $input): array
    {
        $input = trim($input);

        if (preg_match('/\s/u', $input)) {
            $this->reject('URL tidak boleh mengandung spasi.');
        }

        if (strlen($input) > self::MAX_LENGTH) {
            $this->reject('URL terlalu panjang (maksimal '.self::MAX_LENGTH.' karakter).');
        }

        // Tanpa skema (contoh esakip.jemberkab.go.id) dianggap https://. Skema tanpa "//" seperti
        // javascript: atau mailto: tetap ditolak, tetapi host:port (contoh web.id:8080) bukan skema.
        if (! preg_match('~^[a-z][a-z0-9+.\-]*://~i', $input)) {
            if (preg_match('~^([a-z][a-z0-9+.\-]*):(?!\d)~i', $input, $match)) {
                $scheme = strtolower($match[1]);

                $this->reject(in_array($scheme, ['http', 'https'], true)
                    ? 'format URL tidak valid, contoh yang benar: https://esakip.jemberkab.go.id.'
                    : "skema {$scheme} tidak diizinkan, hanya http atau https.");
            }

            $input = 'https://'.ltrim($input, '/');
        }

        preg_match('~^([a-z][a-z0-9+.\-]*):~i', $input, $match);
        $scheme = strtolower($match[1]);

        if (! in_array($scheme, ['http', 'https'], true)) {
            $this->reject("skema {$scheme} tidak diizinkan, hanya http atau https.");
        }

        $parts = parse_url($input);

        if ($parts === false || ! str_starts_with(strtolower($input), $scheme.'://') || empty($parts['host'])) {
            $this->reject('format URL tidak valid.');
        }

        // Menolak trik seperti https://jemberkab.go.id@situs-lain.com
        if (isset($parts['user']) || isset($parts['pass'])) {
            $this->reject('URL tidak boleh memuat nama pengguna atau kata sandi (@).');
        }

        $host = rtrim(mb_strtolower($parts['host']), '.');

        // Domain berhuruf non-latin diubah ke bentuk punycode, contoh bücher.de menjadi xn--bcher-kva.de
        if (preg_match('/[^\x00-\x7F]/', $host) && function_exists('idn_to_ascii')) {
            $host = idn_to_ascii($host, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46) ?: $host;
        }

        if ($host === 'localhost' || str_ends_with($host, '.localhost')) {
            $this->reject('localhost tidak diizinkan.');
        }

        // Host berupa IPv6 ditulis di dalam kurung siku, contoh [::1]
        $bareHost = trim($host, '[]');

        if (filter_var($bareHost, FILTER_VALIDATE_IP) !== false || preg_match('/^[0-9.]+$/', $bareHost)) {
            $this->reject('alamat IP tidak diizinkan, gunakan nama domain.');
        }

        if (! preg_match('/^[a-z0-9.-]+$/', $host) || filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false) {
            $this->reject('nama host tidak valid.');
        }

        // Nama tanpa titik (contoh intranet) bisa di-resolve DNS lokal ke mesin internal
        if (! str_contains($host, '.')) {
            $this->reject('gunakan nama domain lengkap, contoh esakip.jemberkab.go.id.');
        }

        if (! $this->allowsAllDomains() && ! $this->isAllowedHost($host)) {
            $this->reject("domain {$host} tidak termasuk domain yang diizinkan (".implode(', ', $this->allowedDomains).').');
        }

        $url = $this->build($scheme, $host, $parts);

        // Diperiksa ulang karena https:// ditambahkan pada input tanpa skema
        if (strlen($url) > self::MAX_LENGTH) {
            $this->reject('URL terlalu panjang (maksimal '.self::MAX_LENGTH.' karakter).');
        }

        return ['url' => $url, 'host' => $host];
    }

    private function isAllowedHost(string $host): bool
    {
        foreach ($this->allowedDomains as $domain) {
            if ($host === $domain || str_ends_with($host, '.'.$domain)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Susun ulang URL: port bawaan dan fragment dibuang, path "/" di akar disamakan dengan tanpa path.
     *
     * @param  array<string, mixed>  $parts
     */
    private function build(string $scheme, string $host, array $parts): string
    {
        $url = $scheme.'://'.$host;

        $port = $parts['port'] ?? null;
        $defaultPort = $scheme === 'https' ? 443 : 80;

        if ($port !== null && $port !== $defaultPort) {
            $url .= ':'.$port;
        }

        $path = $parts['path'] ?? '';

        if ($path !== '/') {
            $url .= $path;
        }

        if (isset($parts['query']) && $parts['query'] !== '') {
            $url .= '?'.$parts['query'];
        }

        return $url;
    }

    private function reject(string $reason): never
    {
        throw new InvalidArgumentException($reason);
    }
}
