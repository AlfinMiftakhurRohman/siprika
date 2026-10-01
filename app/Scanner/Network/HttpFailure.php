<?php

namespace App\Scanner\Network;

use RuntimeException;

/**
 * Permintaan HTTP gagal di level jaringan (bukan status HTTP).
 */
class HttpFailure extends RuntimeException
{
    public const REFUSED = 'refused';

    public const TLS = 'tls';

    public const TIMEOUT = 'timeout';

    public const DNS = 'dns';

    public const BLOCKED = 'blocked';

    public const OTHER = 'other';

    public function __construct(public readonly string $kind, string $message)
    {
        parent::__construct($message);
    }

    public static function fromMessage(string $message): self
    {
        $code = preg_match('/cURL error (\d+)/', $message, $m) ? (int) $m[1] : null;

        $kind = match (true) {
            $code === 7 => self::REFUSED,
            in_array($code, [35, 60, 58, 59, 66, 77, 80, 83, 90, 91], true) => self::TLS,
            $code === 28 => self::TIMEOUT,
            $code === 6 => self::DNS,
            // Pesan Windows (WinSock) berbeda dari cURL, contoh "did not properly respond after a period of time"
            (bool) preg_match('/timed out|did not properly respond|failed to respond/i', $message) => self::TIMEOUT,
            (bool) preg_match('/refused/i', $message) => self::REFUSED,
            default => self::OTHER,
        };

        return new self($kind, $message);
    }

    /**
     * Kegagalan koneksi socket (stream_socket_client) dari nomor error sistem, supaya label sesuai penyebabnya:
     * 10060/110 waktu habis, 10061/111 ditolak (Windows/Linux). Nomor lain dibaca dari pesannya.
     */
    public static function fromSocketError(int $errno, string $message): self
    {
        return match ($errno) {
            10060, 110 => new self(self::TIMEOUT, $message),
            10061, 111 => new self(self::REFUSED, $message),
            default => self::fromMessage($message),
        };
    }

    /**
     * Gagal karena jaringan (bukan penolakan TLS atau aturan keamanan), sehingga layak diulang (bagian 22.3).
     */
    public function isNetwork(): bool
    {
        return in_array($this->kind, [self::TIMEOUT, self::REFUSED, self::OTHER], true);
    }

    public function kindLabel(): string
    {
        return match ($this->kind) {
            self::REFUSED => 'koneksi ditolak',
            self::TLS => 'handshake TLS gagal',
            self::TIMEOUT => 'waktu habis',
            self::DNS => 'DNS gagal',
            self::BLOCKED => 'diblokir aturan keamanan SIPRIKA',
            default => 'kesalahan jaringan',
        };
    }
}
