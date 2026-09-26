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
     * Kolom yang diisi SIPRIKA. Kolom yang diisi user (I, S, T, U, V, W, AA) dibiarkan kosong,
     * kolom rumus template (L, M, X, Y) dihitung Excel.
     *
     * @return array<string, string|int>
     */
    public static function values(RiskRegisterItem $item, int $number): array
    {
        $notAcceptable = $item->isNotAcceptable();

        return [
            'A' => self::riskNumber($number),
            'B' => (string) config('siprika_risk.risk_type'),
            'C' => $item->asset,
            'D' => $item->threat,
            'E' => $item->vulnerability,
            'F' => $item->category,
            'G' => $item->impact_description,
            'H' => $item->impact_area,
            'J' => $item->impactLabel(),
            'K' => $item->likelihoodLabel(),
            'N' => $notAcceptable ? 'Ya' : '',
            'O' => (int) $item->priority,
            'P' => $notAcceptable ? (string) config('siprika_risk.treatment_option') : '',
            'Q' => $item->action_plan,
            'R' => $item->output,
            'Z' => $item->additional_control,
        ];
    }

    /**
     * Nilai yang tampil di Excel setelah rumus template dihitung: IR (L), Level (M), serta
     * Residual Risk (X, Y) yang bernilai N/A selama kolom U belum diisi "Ya".
     *
     * @return array<string, string|int>
     */
    public static function displayValues(RiskRegisterItem $item, int $number): array
    {
        return self::values($item, $number) + [
            'L' => (int) $item->inherent_risk,
            'M' => $item->risk_level,
            'X' => 'N/A',
            'Y' => 'N/A',
        ];
    }

    public static function riskNumber(int $number): string
    {
        return config('siprika.excel.risk_no_prefix').str_pad((string) $number, 3, '0', STR_PAD_LEFT);
    }
}
