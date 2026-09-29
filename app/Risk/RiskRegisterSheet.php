<?php

namespace App\Risk;

use App\Models\RiskRegisterItem;

/**
 * Isi kolom sheet Perangkat Lunak pada template Risk Register (bagian 25). Dipakai export Excel
 * dan tampilan web supaya keduanya selalu sama.
 */
class RiskRegisterSheet
{
    /**
     * Kolom yang diisi SIPRIKA. Kolom yang diisi staf (S, T, AA) dibiarkan kosong,
     * kolom rumus template (L, M, X, Y) dihitung Excel.
     *
     * @return array<string, string|int>
     */
    public static function values(RiskRegisterItem $item, int $number): array
    {
        $values = [
            'A' => self::riskNumber($number),
            'B' => (string) config('siprika_risk.risk_type'),
            'C' => $item->asset,
            'D' => $item->threat,
            'E' => $item->vulnerability,
            'F' => $item->category,
            'G' => $item->impact_description,
            'H' => $item->impact_area,
            'I' => (string) config('siprika_risk.current_control'),
            'J' => $item->impactLabel(),
            'K' => $item->likelihoodLabel(),
            'N' => (string) config('siprika_risk.treatment_decision'),
            'O' => (int) $item->priority,
            'P' => (string) config('siprika_risk.treatment_option'),
            'Q' => $item->action_plan,
            'R' => $item->output,
            'Z' => $item->additional_control,
        ];

        // Baris lama yang belum dihitung ulang (siprika:recalculate) tidak punya nilai residual
        if ($item->hasResidual()) {
            $values += [
                'U' => (string) config('siprika_risk.residual.exists'),
                'V' => $item->residualImpactLabel(),
                'W' => $item->residualLikelihoodLabel(),
            ];
        }

        return $values;
    }

    /**
     * Nilai yang tampil di Excel setelah rumus template dihitung: IR (L), Level (M), serta
     * RR (X) dan Status residual (Y) yang bernilai N/A jika kolom U bukan "Ya".
     *
     * @return array<string, string|int>
     */
    public static function displayValues(RiskRegisterItem $item, int $number): array
    {
        $values = self::values($item, $number);
        $residual = ($values['U'] ?? null) === 'Ya';

        return $values + [
            'L' => (int) $item->inherent_risk,
            'M' => $item->risk_level,
            'X' => $residual ? (int) $item->residual_risk : 'N/A',
            'Y' => $residual ? $item->residual_status : 'N/A',
        ];
    }

    public static function riskNumber(int $number): string
    {
        return config('siprika.excel.risk_no_prefix').str_pad((string) $number, 3, '0', STR_PAD_LEFT);
    }
}
