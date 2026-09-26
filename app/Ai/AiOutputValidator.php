<?php

namespace App\Ai;

/**
 * Validasi output AI sebelum dipakai (bagian 9 dan 27).
 */
class AiOutputValidator
{
    public const KEYS = ['finding', 'threat', 'vulnerability', 'category', 'impact_description', 'recommendation', 'additional_control'];

    private const MAX_LENGTH = 1000;

    /**
     * @param  array<string, mixed>  $output
     * @param  array<string, mixed>  $input
     * @return string|null alasan penolakan, atau null jika valid
     */
    public function reject(array $output, array $input): ?string
    {
        foreach (self::KEYS as $key) {
            if (! isset($output[$key]) || ! is_string($output[$key]) || trim($output[$key]) === '') {
                return "Kunci {$key} tidak ada atau kosong.";
            }

            if (mb_strlen($output[$key]) > self::MAX_LENGTH) {
                return "Nilai {$key} terlalu panjang.";
            }
        }

        $inputText = strtolower(json_encode($input, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        $outputText = implode("\n", array_map(fn ($key) => $output[$key], self::KEYS));

        // Setiap CVE, URL, dan versi software di jawaban AI harus ada di input
        preg_match_all('/CVE-\d{4}-\d{4,}/i', $outputText, $cves);

        foreach ($cves[0] as $cve) {
            if (! str_contains($inputText, strtolower($cve))) {
                return "CVE {$cve} tidak ada di data input.";
            }
        }

        preg_match_all('/\b(?:https?:\/\/|www\.)[^\s"\'<>]+/i', $outputText, $urls);

        foreach ($urls[0] as $url) {
            if (! str_contains($inputText, strtolower(rtrim($url, '.,;)')))) {
                return "URL {$url} tidak ada di data input.";
            }
        }

        // Versi protokol (TLS 1.2, HTTP/2) bukan versi software, jadi dikecualikan
        preg_match_all('/(?<!TLS |TLSv|SSL |SSLv|HTTP\/)(?<![\d.])\d+\.\d+(?:\.\d+)*/i', $outputText, $versions);

        foreach ($versions[0] as $version) {
            if (! str_contains($inputText, $version)) {
                return "Versi {$version} tidak ada di data input.";
            }
        }

        return null;
    }
}
