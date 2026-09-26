<?php

namespace App\Models;

use App\Enums\ObservationStatus;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

#[Fillable(['check_key', 'label', 'tool', 'status', 'summary', 'raw', 'duration_ms'])]
class ScanObservation extends Model
{
    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'status' => ObservationStatus::class,
            'raw' => 'array',
        ];
    }

    /**
     * @return BelongsTo<ScanTarget, $this>
     */
    public function target(): BelongsTo
    {
        return $this->belongsTo(ScanTarget::class, 'scan_target_id');
    }
}
