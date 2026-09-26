<?php

namespace App\Enums;

enum ScanTargetStatus: string
{
    case Queued = 'QUEUED';
    case Running = 'RUNNING';
    case Completed = 'COMPLETED';
    case Partial = 'PARTIAL';
    case Failed = 'FAILED';
    case Cancelled = 'CANCELLED';

    public function label(): string
    {
        return match ($this) {
            self::Queued => 'Menunggu',
            self::Running => 'Sedang diperiksa',
            self::Completed => 'Selesai',
            self::Partial => 'Sebagian gagal',
            self::Failed => 'Gagal',
            self::Cancelled => 'Dibatalkan',
        };
    }

    public function badgeClass(): string
    {
        return match ($this) {
            self::Queued => 'bg-slate-100 text-slate-700',
            self::Running => 'bg-sky-100 text-sky-800',
            self::Completed => 'bg-emerald-100 text-emerald-800',
            self::Partial => 'bg-amber-100 text-amber-800',
            self::Failed => 'bg-red-100 text-red-800',
            self::Cancelled => 'bg-slate-200 text-slate-600',
        };
    }

    /**
     * Warna bar progress.
     */
    public function barClass(): string
    {
        return match ($this) {
            self::Running => 'bg-sky-600',
            self::Completed => 'bg-emerald-600',
            self::Partial => 'bg-amber-500',
            self::Failed => 'bg-red-600',
            self::Queued, self::Cancelled => 'bg-slate-300',
        };
    }

    /**
     * Target sudah mulai diperiksa, sehingga ada hasil (walaupun sebagian) untuk dilihat.
     */
    public function hasStarted(): bool
    {
        return ! in_array($this, [self::Queued, self::Cancelled], true);
    }

    public function isFinished(): bool
    {
        return in_array($this, [self::Completed, self::Partial, self::Failed, self::Cancelled], true);
    }

    /**
     * Target yang hasilnya bisa ditampilkan dan diekspor.
     */
    public function hasResult(): bool
    {
        return in_array($this, [self::Completed, self::Partial], true);
    }
}
