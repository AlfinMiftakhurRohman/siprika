<?php

namespace App\Ai;

/**
 * Validasi jawaban AI sebelum disimpan atau dipakai (bagian 9 dan 27).
 */
class AiOutputValidator
{
    public const KEYS = ['finding', 'threat', 'vulnerability', 'category', 'impact_description', 'recommendation', 'additional_control'];

    private const MAX_LENGTH = 1000;

    /**
     * @param  array<string, mixed>  $output  jawaban AI
     * @param  array<string, mixed>  $input  informasi jenis finding yang dikirim ke AI (AiInput), sama untuk semua website
     * @param  SiteEvidence  $evidence  evidence finding pada website yang sedang diproses
     * @return string|null alasan penolakan, atau null jika valid
     */
    public function reject(array $output, array $input, SiteEvidence $evidence = new SiteEvidence): ?string
    {
        foreach (self::KEYS as $key) {
            if (! isset($output[$key]) || ! is_string($output[$key]) || trim($output[$key]) === '') {
                return "Kunci {$key} tidak ada atau kosong.";
            }

            if (mb_strlen($output[$key]) > self::MAX_LENGTH) {
                return "Nilai {$key} terlalu panjang.";
            }
        }

        $outputText = implode("\n", array_map(fn ($key) => $output[$key], self::KEYS));
        $generic = strtolower(json_encode($input, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        $known = $generic."\n".$evidence->text;

        foreach (self::references($outputText) as $label => $values) {
            foreach ($values as $value) {
                // Bagian 27: setiap CVE, versi, dan URL harus ada di evidence website yang sedang diproses
                if (! str_contains($known, strtolower($value))) {
                    return "{$label} {$value} tidak ada di evidence website yang sedang diproses.";
                }

                // Ada di evidence tetapi bukan informasi jenis finding: detail khusus website ini
                if (! str_contains($generic, strtolower($value))) {
                    return "{$label} {$value} adalah detail khusus website, padahal teks AI dipakai ulang untuk website lain.";
                }
            }
        }

        foreach ($evidence->details as $detail) {
            if (self::containsWord($outputText, $detail) && ! self::containsWord($generic, $detail)) {
                return "Memuat detail khusus website ({$detail}), padahal teks AI dipakai ulang untuk website lain.";
            }
        }

        return null;
    }

    /**
     * Teks memuat detail sebagai kata utuh, supaya cookie "sid" tidak cocok dengan kata "residual".
     */
    private static function containsWord(string $text, string $detail): bool
    {
        return preg_match('/(?<![\p{L}\p{N}_])'.preg_quote($detail, '/').'(?![\p{L}\p{N}_])/iu', $text) === 1;
    }

    /**
     * CVE, URL, dan versi software yang disebut di teks.
     *
     * @return array<string, list<string>>
     */
    private static function references(string $text): array
    {
        preg_match_all('/CVE-\d{4}-\d{4,}/i', $text, $cves);
        preg_match_all('/\b(?:https?:\/\/|www\.)[^\s"\'<>]+/i', $text, $urls);
        // Versi protokol (TLS 1.2, HTTP/2) bukan versi software, jadi dikecualikan
        preg_match_all('/(?<!TLS |TLSv|SSL |SSLv|HTTP\/)(?<![\d.])\d+\.\d+(?:\.\d+)*/i', $text, $versions);

        return [
            'CVE' => $cves[0],
            'URL' => array_map(fn (string $url) => rtrim($url, '.,;)'), $urls[0]),
            'Versi' => $versions[0],
        ];
    }
}
