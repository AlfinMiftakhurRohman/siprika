<?php

namespace App\Models;

use App\Enums\Severity;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

#[Fillable(['finding_key', 'title', 'description', 'severity', 'cve', 'cvss', 'recommendation', 'sources'])]
class ScanFinding extends Model
{
    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'severity' => Severity::class,
            'cvss' => 'float',
            'sources' => 'array',
        ];
    }

    /**
     * @return BelongsTo<ScanTarget, $this>
     */
    public function target(): BelongsTo
    {
        return $this->belongsTo(ScanTarget::class, 'scan_target_id');
    }

    /**
     * @return HasMany<FindingEvidence, $this>
     */
    public function evidences(): HasMany
    {
        return $this->hasMany(FindingEvidence::class)->orderBy('id');
    }

    /**
     * Hasil Nuclei di luar katalog berseverity info: hanya informasi, tidak menjadi baris Risk Register (bagian 24.4).
     */
    public function isInformational(): bool
    {
        return str_starts_with($this->finding_key, 'nuclei:') && $this->severity === Severity::Info;
    }
}
