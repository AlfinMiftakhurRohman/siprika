<?php

namespace App\Models;

use App\Enums\ScanMode;
use Database\Factories\ScanBatchFactory;
use Illuminate\Database\Eloquent\Attributes\Fillable;
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
