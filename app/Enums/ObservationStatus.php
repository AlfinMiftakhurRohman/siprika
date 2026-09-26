<?php

namespace App\Enums;

enum ObservationStatus: string
{
    case Pass = 'PASS';
    case Fail = 'FAIL';
    case Info = 'INFO';
    case Error = 'ERROR';
    case NotApplicable = 'N/A';
    case NotAssessed = 'NOT ASSESSED';

    public function badgeClass(): string
    {
        return match ($this) {
            self::Pass => 'bg-emerald-100 text-emerald-800',
            self::Fail => 'bg-red-100 text-red-800',
            self::Info => 'bg-sky-100 text-sky-800',
            self::Error => 'bg-amber-100 text-amber-800',
            self::NotApplicable, self::NotAssessed => 'bg-slate-100 text-slate-600',
        };
    }
}
