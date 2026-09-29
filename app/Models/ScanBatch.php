<?php

namespace App\Models;

use App\Enums\ScanMode;
use App\Enums\ScanTargetStatus;
use Database\Factories\ScanBatchFactory;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\HasManyThrough;

#[Fillable(['mode'])]
class ScanBatch extends Model
{
    /** @use HasFactory<ScanBatchFactory> */
    use HasFactory;

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'mode' => ScanMode::class,
        ];
    }

    /**
     * Target dalam batch, sesuai urutan antrean.
     *
     * @return HasMany<ScanTarget, $this>
     */
    public function targets(): HasMany
    {
        return $this->hasMany(ScanTarget::class)->orderBy('position');
    }

    /**
     * Masih ada website yang menunggu atau sedang diperiksa, sehingga batch belum dapat dipindai ulang atau dihapus.
     */
    public function isRunning(): bool
    {
        return $this->targets->contains(fn (ScanTarget $target) => ! $target->status->isFinished());
    }

    /**
     * Batch yang semua websitenya sudah selesai, dibatalkan, atau gagal.
     *
     * @param  Builder<self>  $query
     */
    public function scopeFinished(Builder $query): void
    {
        $query->whereDoesntHave('targets', fn (Builder $targets) => $targets->whereIn('status', [ScanTargetStatus::Queued->value, ScanTargetStatus::Running->value]));
    }

    /**
     * Baris Risk Register semua website dalam batch, urut sesuai antrean lalu prioritas.
     *
     * @return HasManyThrough<RiskRegisterItem, ScanTarget, $this>
     */
    public function riskItems(): HasManyThrough
    {
        return $this->hasManyThrough(RiskRegisterItem::class, ScanTarget::class)
            ->orderBy('scan_targets.position')
            ->orderBy('risk_register_items.priority');
    }
}
