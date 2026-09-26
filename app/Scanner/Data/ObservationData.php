<?php

namespace App\Scanner\Data;

use App\Enums\ObservationStatus;

class ObservationData
{
    /**
     * @param  array<string, mixed>|null  $raw
     */
    public function __construct(
        public readonly string $key,
        public readonly string $label,
        public readonly string $tool,
        public readonly ObservationStatus $status,
        public readonly ?string $summary = null,
        public readonly ?array $raw = null,
    ) {}
}
