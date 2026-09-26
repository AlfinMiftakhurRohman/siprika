<?php

namespace App\Models;

use App\Enums\ScanTargetStatus;
use App\Scanner\ScanProgress;
use Database\Factories\ScanTargetFactory;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

#[Fillable(['position', 'url', 'host', 'status', 'overview', 'progress', 'started_at', 'finished_at', 'error_message'])]
class ScanTarget extends Model
{
    /** @use HasFactory<ScanTargetFactory> */
    use HasFactory;

    /**
     * Nilai awal saat target baru dibuat.
     *
     * @var array<string, mixed>
     */
    protected $attributes = [
        'status' => 'QUEUED',
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'status' => ScanTargetStatus::class,
            'overview' => 'array',
            'progress' => 'array',
            'started_at' => 'datetime',
            'finished_at' => 'datetime',
        ];
    }

    /**
     * @return BelongsTo<ScanBatch, $this>
     */
    public function batch(): BelongsTo
    {
        return $this->belongsTo(ScanBatch::class, 'scan_batch_id');
    }

    /**
     * @return HasMany<ScanObservation, $this>
     */
    public function observations(): HasMany
    {
        return $this->hasMany(ScanObservation::class)->orderBy('id');
    }

    /**
     * @return HasMany<ScanFinding, $this>
     */
    public function findings(): HasMany
    {
        return $this->hasMany(ScanFinding::class);
    }

    /**
     * @return HasMany<RiskRegisterItem, $this>
     */
    public function riskItems(): HasMany
    {
        return $this->hasMany(RiskRegisterItem::class)->orderBy('priority');
    }

    /**
     * Persentase progress: 0 selama menunggu, 100 setelah selesai, selain itu dari bobot tahap (ScanProgress).
     */
    public function progressPercent(): int
    {
        return match (true) {
            $this->status === ScanTargetStatus::Queued, $this->status === ScanTargetStatus::Cancelled => 0,
            $this->status->isFinished() => 100,
            default => ScanProgress::percent($this->progress ?? []),
        };
    }

    /**
     * Label tahap yang sedang berjalan, contoh "Nuclei", atau null jika tidak ada.
     */
    public function currentStep(): ?string
    {
        return collect($this->progress ?? [])->firstWhere('status', ScanProgress::RUNNING)['label'] ?? null;
    }

    /**
     * Nama aset untuk kolom Aset Risk Register, contoh: "Website Dinas X (dinasx.jemberkab.go.id)".
     */
    public function assetName(): string
    {
        // Title halaman blokir WAF/CDN (contoh "Just a moment...") bukan nama website
        $title = empty($this->overview['waf_blocked']) ? trim((string) ($this->overview['title'] ?? '')) : '';

        if ($title === '') {
            return "Website {$this->host}";
        }

        $title = mb_strimwidth($title, 0, 120, '...');

        return (str_starts_with(mb_strtolower($title), 'website') ? $title : "Website {$title}")." ({$this->host})";
    }
}
