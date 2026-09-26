<?php

namespace App\Scanner\Checks;

use App\Enums\ObservationStatus;
use App\Scanner\Fingerprint;
use App\Scanner\ScanContext;

/**
 * Deteksi teknologi dari header, cookie, dan HTML halaman utama.
 */
class TechnologyCheck implements Check
{
    public function key(): string
    {
        return 'technology';
    }

    public function label(): string
    {
        return 'Technology Detection';
    }

    public function run(ScanContext $context): void
    {
        if ($context->homepage === null) {
            $context->observe('technology', 'Technology Detection', 'internal', ObservationStatus::NotAssessed, 'Halaman utama tidak dapat diakses.');

            return;
        }

        $technologies = Fingerprint::technologies($context->homepage);
        $context->addTechnologies($technologies);

        $summary = $technologies === []
            ? 'Tidak ada teknologi yang dikenali dari halaman utama.'
            : Fingerprint::describe($technologies).'.';

        if ($context->wafBlocked) {
            $summary .= ' Respons berupa halaman blokir WAF/CDN, hasil bisa tidak mewakili website aslinya.';
        }

        $context->observe('technology', 'Technology Detection', 'internal', ObservationStatus::Info, $summary, ['technologies' => $technologies]);
    }
}
