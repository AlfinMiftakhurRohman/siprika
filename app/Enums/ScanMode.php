<?php

namespace App\Enums;

use App\Scanner\Checks\Check;
use App\Scanner\Checks\CookieCheck;
use App\Scanner\Checks\ExposureCheck;
use App\Scanner\Checks\HttpCheck;
use App\Scanner\Checks\NucleiCheck;
use App\Scanner\Checks\PortCheck;
use App\Scanner\Checks\SecurityHeadersCheck;
use App\Scanner\Checks\TargetValidationCheck;
use App\Scanner\Checks\TechnologyCheck;
use App\Scanner\Checks\TestsslCheck;
use App\Scanner\Checks\TlsCheck;
use App\Scanner\Checks\WhatWebCheck;
use App\Scanner\Checks\ZapPassiveCheck;

enum ScanMode: string
{
    case Quick = 'quick';
    case Standard = 'standard';

    /**
     * Urutan pemeriksaan Mode Standar. Mode Cepat memakai sebagian dari daftar ini (bagian 3 dan 4).
     *
     * @var list<class-string<Check>>
     */
    public const STANDARD_CHECKS = [
        TargetValidationCheck::class,
        HttpCheck::class,
        SecurityHeadersCheck::class,
        CookieCheck::class,
        TechnologyCheck::class,
        TlsCheck::class,
        ExposureCheck::class,
        PortCheck::class,
        NucleiCheck::class,
        TestsslCheck::class,
        WhatWebCheck::class,
        ZapPassiveCheck::class,
    ];

    /**
     * @var list<class-string<Check>>
     */
    public const QUICK_CHECKS = [
        TargetValidationCheck::class,
        HttpCheck::class,
        SecurityHeadersCheck::class,
        CookieCheck::class,
        TechnologyCheck::class,
        TlsCheck::class,
        ExposureCheck::class,
        NucleiCheck::class,
    ];

    public function label(): string
    {
        return match ($this) {
            self::Quick => 'Cepat',
            self::Standard => 'Standar',
        };
    }

    public function description(): string
    {
        return match ($this) {
            self::Quick => 'Gambaran umum dalam waktu singkat: validasi DNS, HTTP, security headers, cookie, TLS dasar, teknologi, exposure terbatas, dan Nuclei profil ringan. Maksimal '.intdiv($this->timeout(), 60).' menit per website.',
            self::Standard => 'Semua pemeriksaan Mode Cepat ditambah exposure lengkap, port/web service (Nmap), Nuclei termasuk CVE, TLS lengkap (testssl.sh), dan WhatWeb. Tool eksternal yang belum dipasang dicatat NOT ASSESSED.',
        };
    }

    /**
     * @return list<class-string<Check>>
     */
    public function checks(): array
    {
        return match ($this) {
            self::Quick => self::QUICK_CHECKS,
            self::Standard => self::STANDARD_CHECKS,
        };
    }

    /**
     * Pemeriksaan Mode Standar yang tidak dijalankan pada mode ini.
     *
     * @return list<class-string<Check>>
     */
    public function skippedChecks(): array
    {
        return array_values(array_diff(self::STANDARD_CHECKS, $this->checks()));
    }

    /**
     * Batas waktu total pemeriksaan satu website (detik).
     */
    public function timeout(): int
    {
        return match ($this) {
            self::Quick => (int) config('siprika.scan.quick_target_timeout'),
            self::Standard => (int) config('siprika.scan.target_timeout'),
        };
    }
}
