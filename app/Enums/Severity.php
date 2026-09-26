<?php

namespace App\Enums;

enum Severity: string
{
    case Info = 'info';
    case Low = 'low';
    case Medium = 'medium';
    case High = 'high';
    case Critical = 'critical';

    public static function fromLoose(?string $value): self
    {
        return self::tryFrom(strtolower(trim((string) $value))) ?? self::Info;
    }

    public function rank(): int
    {
        return match ($this) {
            self::Info => 0,
            self::Low => 1,
            self::Medium => 2,
            self::High => 3,
            self::Critical => 4,
        };
    }

    public function label(): string
    {
        return match ($this) {
            self::Info => 'Info',
            self::Low => 'Rendah',
            self::Medium => 'Sedang',
            self::High => 'Tinggi',
            self::Critical => 'Kritis',
        };
    }

    public function badgeClass(): string
    {
        return match ($this) {
            self::Info => 'bg-slate-100 text-slate-700',
            self::Low => 'bg-sky-100 text-sky-800',
            self::Medium => 'bg-amber-100 text-amber-800',
            self::High => 'bg-orange-100 text-orange-800',
            self::Critical => 'bg-red-100 text-red-800',
        };
    }
}
