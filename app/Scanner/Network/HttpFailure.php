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
            str_contains(strtolower($message), 'timed out') => self::TIMEOUT,
            str_contains(strtolower($message), 'refused') => self::REFUSED,
            default => self::OTHER,
        };

        return new self($kind, $message);
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
