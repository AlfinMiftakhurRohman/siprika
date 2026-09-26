<?php

namespace App\Risk;

use App\Enums\Severity;
use App\Models\AiAnalysis;
use App\Models\FindingEvidence;
use App\Models\RiskRegisterItem;
use App\Models\ScanFinding;
use App\Models\ScanTarget;

/**
 * Menilai risiko setiap finding memakai aturan di config/siprika_catalog.php dan
 * matriks template di config/siprika_risk.php (bagian 24 dan 25).
 */
class RiskEngine
{
    /**
     * Susun ulang baris Risk Register untuk satu website.
     */
    public function assess(ScanTarget $target): void
    {
        $target->riskItems()->delete();

        $findings = $target->findings()->with('evidences')->get();
        // Jika AI tidak aktif, kolom deskriptif memakai teks katalog walaupun ada hasil AI tersimpan (bagian 29)
        $aiAnalyses = config('siprika.ai.enabled')
            ? AiAnalysis::whereIn('finding_key', $findings->pluck('finding_key'))->get()->keyBy('finding_key')
            : collect();

        $rows = [];

        foreach ($findings as $finding) {
            $rule = $this->rule($finding);

            if ($rule !== null) {
                $rows[] = $this->buildRow($target, $finding, $rule, $aiAnalyses->get($finding->finding_key));
            }
        }

        // Prioritas: IR tertinggi di website yang sama mendapat prioritas 1
        usort($rows, fn (array $a, array $b) => [$b['inherent_risk'], $b['impact'], $b['likelihood'], $a['finding_key']]
            <=> [$a['inherent_risk'], $a['impact'], $a['likelihood'], $b['finding_key']]);

        foreach ($rows as $index => $row) {
            $target->riskItems()->create($row + ['priority' => $index + 1]);
        }
    }

    /**
     * Aturan untuk finding, atau null jika finding tidak menjadi baris Risk Register.
     *
     * @return array<string, mixed>|null
     */
    public function rule(ScanFinding $finding): ?array
    {
        $catalog = config("siprika_catalog.{$finding->finding_key}");

        if ($catalog !== null) {
            return $catalog;
        }

        if (! str_starts_with($finding->finding_key, 'nuclei:')) {
            return null;
        }

        $nuclei = config('siprika_risk.nuclei');
        $impact = $nuclei['impact_by_severity'][$finding->severity->value] ?? null;

        // Severity info hanya tampil di tab Findings
        if ($impact === null || $finding->severity === Severity::Info) {
            return null;
        }

        return [
            'category' => $nuclei['category'],
            'threat' => $nuclei['threat'],
            'vulnerability' => $finding->cve ? $nuclei['vulnerability_cve'] : $nuclei['vulnerability_default'],
            'impact_area' => $nuclei['impact_area'],
            'impact' => $impact,
            'likelihood' => $nuclei['likelihood_default'],
            'impact_description' => $nuclei['impact_description'],
            'recommendation' => $nuclei['recommendation'],
            'output' => $nuclei['output'],
            'additional_control' => $nuclei['additional_control'],
        ];
    }

    public static function inherentRisk(int $impact, int $likelihood): int
    {
        return config('siprika_risk.matrix')[$likelihood][$impact];
    }

    public static function level(int $impact, int $likelihood): string
    {
        return config('siprika_risk.levels')[$likelihood][$impact];
    }

    public static function status(int $inherentRisk): string
    {
        return $inherentRisk >= (int) config('siprika_risk.not_acceptable_threshold')
            ? RiskRegisterItem::NOT_ACCEPTABLE
            : RiskRegisterItem::ACCEPTABLE;
    }

    /**
     * @param  array<string, mixed>  $rule
     * @param  AiAnalysis|null  $ai  hasil AI untuk kunci finding ini, null berarti memakai teks katalog
     * @return array<string, mixed>
     */
    private function buildRow(ScanTarget $target, ScanFinding $finding, array $rule, ?AiAnalysis $ai): array
    {
        $impact = (int) $rule['impact'];
        $likelihood = (int) $rule['likelihood'];
        $inherentRisk = self::inherentRisk($impact, $likelihood);

        return [
            'scan_finding_id' => $finding->id,
            'finding_key' => $finding->finding_key,
            'asset' => $target->assetName(),
            'threat' => $rule['threat'],
            'vulnerability' => $this->vulnerabilityText($rule['vulnerability'], $finding),
            'category' => $rule['category'],
            'impact_description' => $ai?->impact_description ?? $rule['impact_description'],
            'impact_area' => $rule['impact_area'],
            'impact' => $impact,
            'likelihood' => $likelihood,
            'inherent_risk' => $inherentRisk,
            'risk_level' => self::level($impact, $likelihood),
            'risk_status' => self::status($inherentRisk),
            'action_plan' => $ai?->recommendation ?? $rule['recommendation'],
            'output' => $rule['output'],
            'additional_control' => $ai?->additional_control ?? $rule['additional_control'],
            'text_source' => $ai !== null ? 'ai' : 'catalog',
        ];
    }

    /**
     * Kerawanan dari katalog ditambah detail evidence di akhir (bagian 23.2).
     */
    private function vulnerabilityText(string $base, ScanFinding $finding): string
    {
        // Evidence Nuclei ("template ... cocok pada ...") hanya dipakai jika scanner lain tidak menemukan hal yang sama,
        // karena penjelasan pemeriksaan bawaan atau testssl.sh lebih mudah dibaca di Risk Register
        $described = $finding->evidences->reject(fn (FindingEvidence $e) => $e->source === 'nuclei');

        $details = ($described->isNotEmpty() ? $described : $finding->evidences)
            ->sortBy(fn (FindingEvidence $e) => $e->source === 'internal' ? 0 : 1)
            ->pluck('detail')
            ->unique()
            ->values();

        if (str_starts_with($finding->finding_key, 'nuclei:')) {
            $details = collect([$finding->title.($finding->cve ? " ({$finding->cve})" : '')]);
        }

        if ($details->isEmpty()) {
            return $base;
        }

        $text = $details->take(3)->implode('; ');

        if ($details->count() > 3) {
            $text .= '; dan '.($details->count() - 3).' temuan lain';
        }

        return $base.' ('.mb_strimwidth($text, 0, 400, '...').')';
    }
}
