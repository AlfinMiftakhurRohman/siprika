<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

#[Fillable([
    'scan_finding_id', 'finding_key', 'asset', 'threat', 'vulnerability', 'category', 'impact_description',
    'impact_area', 'impact', 'likelihood', 'inherent_risk', 'risk_level', 'risk_status', 'priority',
    'action_plan', 'output', 'additional_control', 'text_source',
])]
class RiskRegisterItem extends Model
{
    public const NOT_ACCEPTABLE = 'Not Acceptable';

    public const ACCEPTABLE = 'Acceptable';

    /**
     * @return BelongsTo<ScanTarget, $this>
     */
    public function target(): BelongsTo
    {
        return $this->belongsTo(ScanTarget::class, 'scan_target_id');
    }

    /**
     * @return BelongsTo<ScanFinding, $this>
     */
    public function finding(): BelongsTo
    {
        return $this->belongsTo(ScanFinding::class, 'scan_finding_id');
    }

    public function isNotAcceptable(): bool
    {
        return $this->risk_status === self::NOT_ACCEPTABLE;
    }

    /**
     * Asal teks kolom Dampak, Rencana Aksi, dan Kontrol Tambahan.
     */
    public function textSourceLabel(): string
    {
        return $this->text_source === 'ai' ? 'AI' : 'katalog';
    }

    public function impactLabel(): string
    {
        return config('siprika_risk.impact_labels')[$this->impact];
    }

    public function likelihoodLabel(): string
    {
        return config('siprika_risk.likelihood_labels')[$this->likelihood];
    }
}
