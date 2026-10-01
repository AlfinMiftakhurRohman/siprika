<?php

namespace App\Scanner\Network;

use Carbon\CarbonImmutable;

/**
 * Pemeriksaan TLS memakai stream OpenSSL bawaan PHP.
 * Tanpa CA bundle, PHP di Windows memakai certificate store Windows.
 */
class StreamTlsInspector implements TlsInspector
{
    private const METHODS = [
        'TLSv1.0' => STREAM_CRYPTO_METHOD_TLSv1_0_CLIENT,
        'TLSv1.1' => STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT,
        'TLSv1.2' => STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT,
        'TLSv1.3' => STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT,
    ];

    public function inspect(string $host, string $ip, int $port = 443): TlsReport
    {
        $result = $this->connect($host, $ip, $port, [
            'verify_peer' => false,
            'verify_peer_name' => false,
            'allow_self_signed' => true,
            'capture_peer_cert' => true,
            'capture_peer_cert_chain' => true,
        ]);

        if ($result['stream'] === false) {
            // errno 0: koneksi terbentuk tetapi handshake TLS gagal
            throw $result['errno'] !== 0 ? HttpFailure::fromSocketError($result['errno'], $result['error']) : new HttpFailure(HttpFailure::TLS, $result['error']);
        }

        $params = stream_context_get_params($result['stream'])['options']['ssl'] ?? [];
        $meta = stream_get_meta_data($result['stream'])['crypto'] ?? [];
        fclose($result['stream']);

        $cert = isset($params['peer_certificate']) ? openssl_x509_parse($params['peer_certificate']) : false;
        $chain = $params['peer_certificate_chain'] ?? [];

        $verifyError = $this->verify($host, $ip, $port);

        return new TlsReport(
            subject: $cert['subject']['CN'] ?? null,
            subjectAltNames: $cert ? $this->altNames($cert) : [],
            issuer: $cert ? $this->issuerName($cert) : null,
            validFrom: isset($cert['validFrom_time_t']) ? CarbonImmutable::createFromTimestamp($cert['validFrom_time_t']) : null,
            validTo: isset($cert['validTo_time_t']) ? CarbonImmutable::createFromTimestamp($cert['validTo_time_t']) : null,
            selfSigned: $cert !== false && ($cert['subject'] ?? null) == ($cert['issuer'] ?? null),
            chainLength: count($chain),
            protocol: $meta['protocol'] ?? null,
            cipher: $meta['cipher_name'] ?? null,
            verified: $verifyError === null,
            verifyError: $verifyError,
        );
    }

    public function probeProtocol(string $host, string $ip, string $version, int $port = 443): string
    {
        $result = $this->connect($host, $ip, $port, [
            'verify_peer' => false,
            'verify_peer_name' => false,
            'allow_self_signed' => true,
            'crypto_method' => self::METHODS[$version],
            'security_level' => 0,
            'ciphers' => 'DEFAULT@SECLEVEL=0',
        ]);

        if ($result['stream'] !== false) {
            $protocol = stream_get_meta_data($result['stream'])['crypto']['protocol'] ?? null;
            fclose($result['stream']);

            // OpenSSL melaporkan TLS 1.0 sebagai "TLSv1"
            $expected = $version === 'TLSv1.0' ? 'TLSv1' : $version;

            return $protocol === null || $protocol === $expected ? 'accepted' : 'rejected';
        }

        $error = strtolower($result['error'].' '.$result['openssl']);

        if (str_contains($error, 'no protocols available') || str_contains($error, 'no ciphers available')) {
            return 'unsupported';
        }

        return $result['errno'] !== 0 ? 'error' : 'rejected';
    }

    /**
     * Null jika verifikasi berhasil, selain itu pesan error.
     */
    private function verify(string $host, string $ip, int $port): ?string
    {
        $options = ['verify_peer' => true, 'verify_peer_name' => true];
        $caBundle = config('siprika.scan.ca_bundle');

        if ($caBundle) {
            $options['cafile'] = $caBundle;
        }

        $result = $this->connect($host, $ip, $port, $options);

        if ($result['stream'] !== false) {
            fclose($result['stream']);

            return null;
        }

        // Di Windows (certificate store) PHP hanya memberi pesan umum "Unable to connect to ssl://... (Unknown error)"
        $message = trim(preg_replace('/stream_socket_client\(\):\s*/', '', $result['openssl'] ?: $result['error']));

        return $message === '' || preg_match('/^Unable to connect to ssl:\/\/\S+ \(Unknown error\)$/', $message)
            ? 'verifikasi ke trust store sistem gagal'
            : $message;
    }

    /**
     * @param  array<string, mixed>  $ssl
     * @return array{stream: resource|false, errno: int, error: string, openssl: string}
     */
    private function connect(string $host, string $ip, int $port, array $ssl): array
    {
        // Kosongkan antrean error OpenSSL dari koneksi sebelumnya
        while (openssl_error_string() !== false);

        $context = stream_context_create(['ssl' => $ssl + ['peer_name' => $host, 'SNI_enabled' => true]]);
        $address = str_contains($ip, ':') ? "[{$ip}]" : $ip;
        $warning = '';

        set_error_handler(function (int $no, string $message) use (&$warning) {
            $warning = $message;

            return true;
        });

        try {
            $stream = stream_socket_client(
                "ssl://{$address}:{$port}", $errno, $errstr,
                (float) config('siprika.scan.connect_timeout'), STREAM_CLIENT_CONNECT, $context
            );
        } finally {
            restore_error_handler();
        }

        if ($stream !== false) {
            stream_set_timeout($stream, (int) config('siprika.scan.http_timeout'));
        }

        $openssl = [];

        while (($message = openssl_error_string()) !== false) {
            $openssl[] = $message;
        }

        return [
            'stream' => $stream,
            'errno' => (int) $errno,
            'error' => trim($errstr.' '.$warning),
            'openssl' => implode('; ', $openssl),
        ];
    }

    /**
     * @param  array<string, mixed>  $cert
     * @return list<string>
     */
    private function altNames(array $cert): array
    {
        preg_match_all('/DNS:([^,\s]+)/', (string) ($cert['extensions']['subjectAltName'] ?? ''), $matches);

        return $matches[1];
    }

    /**
     * @param  array<string, mixed>  $cert
     */
    private function issuerName(array $cert): ?string
    {
        $issuer = $cert['issuer'] ?? [];
        $parts = [];

        foreach (['CN', 'O'] as $field) {
            if (isset($issuer[$field])) {
                $parts[] = is_array($issuer[$field]) ? implode(' ', $issuer[$field]) : $issuer[$field];
            }
        }

        return $parts === [] ? null : implode(', ', array_unique($parts));
    }
}
