<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

#[Fillable([
    'scan_finding_id', 'finding_key', 'asset', 'threat', 'vulnerability', 'category', 'impact_description',
    'impact_area', 'impact', 'likelihood', 'inherent_risk', 'risk_level', 'risk_status',
    'residual_impact', 'residual_likelihood', 'residual_risk', 'residual_status', 'priority',
    'action_plan', 'output', 'additional_control', 'text_source',
])]
class RiskRegisterItem extends Model
{
    public const NOT_ACCEPTABLE = 'Not Acceptable';

    public const ACCEPTABLE = 'Acceptable';

    /**
     * Level risiko dari tertinggi, dengan warna sel (sheet Risk Register) dan warna penanda (ringkasan).
     *
     * @var array<string, array{cell: string, dot: string}>
     */
    public const LEVELS = [
        'Sangat Tinggi' => ['cell' => 'bg-red-200', 'dot' => 'bg-red-600'],
        'Tinggi' => ['cell' => 'bg-orange-200', 'dot' => 'bg-orange-500'],
        'Sedang' => ['cell' => 'bg-yellow-100', 'dot' => 'bg-yellow-400'],
        'Rendah' => ['cell' => 'bg-emerald-100', 'dot' => 'bg-emerald-500'],
        'Sangat Rendah' => ['cell' => 'bg-sky-50', 'dot' => 'bg-sky-400'],
    ];

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
     * Residual Risk sudah dihitung (baris lama belum, sampai php artisan siprika:recalculate).
     */
    public function hasResidual(): bool
    {
        return $this->residual_impact !== null && $this->residual_likelihood !== null;
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

    public function residualImpactLabel(): ?string
    {
        return $this->residual_impact !== null ? config('siprika_risk.impact_labels')[$this->residual_impact] : null;
    }

    public function residualLikelihoodLabel(): ?string
    {
        return $this->residual_likelihood !== null ? config('siprika_risk.likelihood_labels')[$this->residual_likelihood] : null;
    }
}
