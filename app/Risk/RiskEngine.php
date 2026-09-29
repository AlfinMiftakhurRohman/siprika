<?php

namespace App\Risk;

use App\Ai\AiInput;
use App\Ai\AiOutputValidator;
use App\Ai\SiteEvidence;
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
    public function __construct(private AiOutputValidator $validator = new AiOutputValidator) {}

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
                $rows[] = $this->buildRow($target, $finding, $rule, $this->validAnalysis($aiAnalyses->get($finding->finding_key), $target, $finding, $rule));
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
     * Hasil AI tersimpan dipakai hanya jika lolos validasi terhadap evidence website ini (bagian 27), karena
     * hasil itu dibuat saat memeriksa website lain. Jika tidak lolos, dipakai teks katalog.
     *
     * @param  array<string, mixed>  $rule
     */
    private function validAnalysis(?AiAnalysis $analysis, ScanTarget $target, ScanFinding $finding, array $rule): ?AiAnalysis
    {
        if ($analysis === null) {
            return null;
        }

        $reason = $this->validator->reject($analysis->only(AiOutputValidator::KEYS), AiInput::build($finding, $rule), SiteEvidence::from($finding, $target));

        return $reason === null ? $analysis : null;
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

    /**
     * Nilai risiko dari tabel RiskMatrix template, dipakai untuk IR maupun RR.
     */
    public static function riskValue(int $impact, int $likelihood): int
    {
        return config('siprika_risk.matrix')[$likelihood][$impact];
    }

    /**
     * Dampak dan kemungkinan residual (bagian 24.6): dampak tetap, kemungkinan turun sesuai config.
     *
     * @return array{0: int, 1: int}
     */
    public static function residual(int $impact): array
    {
        return [
            (int) (config('siprika_risk.residual.impact') ?? $impact),
            (int) config('siprika_risk.residual.likelihood'),
        ];
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
        $inherentRisk = self::riskValue($impact, $likelihood);
        [$residualImpact, $residualLikelihood] = self::residual($impact);
        $residualRisk = self::riskValue($residualImpact, $residualLikelihood);

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
            'residual_impact' => $residualImpact,
            'residual_likelihood' => $residualLikelihood,
            'residual_risk' => $residualRisk,
            'residual_status' => self::status($residualRisk),
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
        if (str_starts_with($finding->finding_key, 'nuclei:')) {
            $details = collect([$finding->title.($finding->cve ? " ({$finding->cve})" : '')]);
        } else {
            // Satu penjelasan per endpoint dari sumber yang paling mudah dibaca: pemeriksaan bawaan, lalu tool lain
            // (testssl.sh, ZAP), lalu Nuclei ("template ... cocok pada ..."). Sumber lain untuk endpoint yang sama
            // menyatakan hal yang sama sehingga tidak diulang, sedangkan endpoint yang hanya ditemukan tool tetap tampil.
            $details = $finding->evidences
                ->sortBy(fn (FindingEvidence $e) => match ($e->source) {
                    'internal' => 0,
                    'nuclei' => 2,
                    default => 1,
                })
                ->groupBy(fn (FindingEvidence $e) => rtrim(strtolower((string) $e->endpoint), '/'))
                ->flatMap(fn ($group) => $group->where('source', $group->first()->source)->pluck('detail'))
                ->unique()
                ->values();
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
