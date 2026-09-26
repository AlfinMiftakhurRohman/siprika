<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

#[Fillable(['source', 'endpoint', 'detail', 'raw'])]
class FindingEvidence extends Model
{
    protected $table = 'finding_evidences';

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'raw' => 'array',
        ];
    }

    /**
     * @return BelongsTo<ScanFinding, $this>
     */
    public function finding(): BelongsTo
    {
        return $this->belongsTo(ScanFinding::class, 'scan_finding_id');
    }
}
