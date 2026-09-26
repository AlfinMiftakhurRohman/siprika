<?php

namespace App\Scanner\Checks;

use App\Enums\ObservationStatus;
use App\Scanner\ScanContext;

/**
 * OWASP ZAP bersifat opsional (bagian 4) dan belum diintegrasikan.
 * Dicatat NOT ASSESSED supaya terlihat di Coverage.
 */
class ZapPassiveCheck implements Check
{
    public function key(): string
    {
        return 'zap-passive';
    }

    public function label(): string
    {
        return 'OWASP ZAP Passive';
    }

    public function run(ScanContext $context): void
    {
        $context->observe('zap-passive', 'OWASP ZAP Passive', 'zap', ObservationStatus::NotAssessed, 'OWASP ZAP bersifat opsional dan belum diintegrasikan pada versi ini. Analisis header dan cookie pasif sudah dilakukan pemeriksaan bawaan.');
    }
}
