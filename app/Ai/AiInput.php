<?php

namespace App\Ai;

use App\Models\ScanFinding;

/**
 * JSON finding hasil normalizer yang dikirim ke AI, tanpa URL atau output mentah scanner (bagian 27).
 *
 * Hasil AI disimpan per kunci finding dan dipakai ulang untuk website lain, jadi input hanya berisi
 * informasi jenis finding (katalog atau template Nuclei) yang sama untuk semua website, bukan evidence
 * website tertentu seperti nama host, cookie, atau versi. Detail per website masuk kolom Kerawanan lewat RiskEngine.
 */
class AiInput
{
    /**
     * @param  array<string, mixed>|null  $rule  aturan RiskEngine untuk finding ini
     * @return array<string, mixed>
     */
    public static function build(ScanFinding $finding, ?array $rule): array
    {
        $stripUrls = fn (?string $text) => $text === null ? null : trim(preg_replace('/\b(?:https?:\/\/|www\.)[^\s"\'<>]+/i', '[url]', $text));

        return array_filter([
            'finding_key' => $finding->finding_key,
            'title' => $finding->title,
            'description' => $stripUrls($finding->description),
            'severity' => $finding->severity->value,
            'cve' => $finding->cve,
            'cvss' => $finding->cvss,
            'category' => $rule['category'] ?? null,
            'threat' => $rule['threat'] ?? null,
            'vulnerability' => $rule['vulnerability'] ?? null,
        ], fn ($value) => $value !== null && $value !== []);
    }
}
