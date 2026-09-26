<?php

namespace App\Scanner;

use App\Enums\Severity;
use App\Models\ScanTarget;
use App\Scanner\Data\FindingData;

/**
 * Menyimpan finding dengan deduplikasi: temuan dengan kunci sama dari beberapa scanner
 * menjadi satu finding dengan beberapa evidence (bagian 11).
 */
class FindingRecorder
{
    /**
     * @param  list<FindingData>  $findings
     */
    public function record(ScanTarget $target, array $findings): void
    {
        $grouped = [];

        foreach ($findings as $finding) {
            $grouped[$finding->key][] = $finding;
        }

        foreach ($grouped as $key => $items) {
            $catalog = config("siprika_catalog.{$key}");
            $severity = $catalog !== null
                ? Severity::fromLoose($catalog['severity'])
                : $this->highestSeverity($items);

            $model = $target->findings()->updateOrCreate(['finding_key' => $key], [
                'title' => $catalog['title'] ?? $this->firstFilled($items, 'title') ?? $key,
                'description' => $catalog['description'] ?? $this->firstFilled($items, 'description'),
                'severity' => $severity,
                'cve' => $this->firstFilled($items, 'cve'),
                'cvss' => $this->firstFilled($items, 'cvss'),
                'recommendation' => $catalog['recommendation'] ?? $this->firstFilled($items, 'recommendation'),
                'sources' => array_values(array_unique(array_map(fn (FindingData $f) => $f->source, $items))),
            ]);

            $seen = [];

            foreach ($items as $item) {
                $signature = $item->source.'|'.$item->endpoint.'|'.$item->detail;

                if (isset($seen[$signature])) {
                    continue;
                }

                $seen[$signature] = true;
                $model->evidences()->create([
                    'source' => $item->source,
                    'endpoint' => $item->endpoint !== null ? mb_substr($item->endpoint, 0, 2048) : null,
                    'detail' => $item->detail,
                    'raw' => $item->raw,
                ]);
            }
        }
    }

    /**
     * @param  list<FindingData>  $items
     */
    private function highestSeverity(array $items): Severity
    {
        $highest = Severity::Info;

        foreach ($items as $item) {
            $severity = Severity::fromLoose($item->severity);

            if ($severity->rank() > $highest->rank()) {
                $highest = $severity;
            }
        }

        return $highest;
    }

    /**
     * @param  list<FindingData>  $items
     */
    private function firstFilled(array $items, string $property): mixed
    {
        foreach ($items as $item) {
            if ($item->{$property} !== null && $item->{$property} !== '') {
                return $item->{$property};
            }
        }

        return null;
    }
}
