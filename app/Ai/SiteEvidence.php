<?php

namespace App\Ai;

use App\Models\FindingEvidence;
use App\Models\ScanFinding;
use App\Models\ScanTarget;
use App\Scanner\CookieRules;

/**
 * Evidence satu finding pada website yang sedang diproses, untuk validasi jawaban AI (bagian 27):
 * - text: semua evidence, tempat mencari CVE, versi, dan URL yang disebut AI;
 * - details: detail khusus website (URL, host, path atau nama file, nama cookie) yang tidak boleh
 *   ada di teks AI karena teks itu disimpan per kunci finding dan dipakai ulang untuk website lain.
 */
class SiteEvidence
{
    /**
     * @param  list<string>  $details
     */
    public function __construct(
        public readonly string $text = '',
        public readonly array $details = [],
    ) {}

    /**
     * Evidence finding harus sudah dimuat (relasi evidences).
     */
    public static function from(ScanFinding $finding, ScanTarget $target): self
    {
        $texts = [$target->url, $target->host];
        $details = [$target->url, $target->host];

        foreach ($finding->evidences as $evidence) {
            /** @var FindingEvidence $evidence */
            $texts[] = (string) $evidence->endpoint;
            $texts[] = (string) $evidence->detail;
            $texts[] = json_encode($evidence->raw ?? [], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

            array_push($details, ...self::endpointDetails((string) $evidence->endpoint));
            array_push($details, ...self::rawDetails($evidence->raw ?? []));
        }

        $details = array_values(array_unique(array_filter(
            array_map(fn (string $detail) => trim($detail), $details),
            fn (string $detail) => mb_strlen($detail) >= 3,
        )));

        return new self(strtolower(implode("\n", $texts)), $details);
    }

    /**
     * URL, host, dan path dari endpoint, contoh https://web.id/.git/config menjadi web.id, /.git/config, .git/config.
     *
     * @return list<string>
     */
    private static function endpointDetails(string $endpoint): array
    {
        if ($endpoint === '') {
            return [];
        }

        $parts = parse_url($endpoint) ?: [];
        $details = [$endpoint, (string) ($parts['host'] ?? '')];

        return [...$details, ...self::pathDetails((string) ($parts['path'] ?? ''))];
    }

    /**
     * Path dan nama file. Nama folder saja (contoh "uploads") tidak dihitung karena juga kata umum.
     *
     * @return list<string>
     */
    private static function pathDetails(string $path): array
    {
        if ($path === '' || $path === '/') {
            return [];
        }

        $relative = ltrim($path, '/');
        $details = [$path];

        // Contoh ".git/config" atau "backup.sql", bukan "uploads/"
        if (str_contains(rtrim($relative, '/'), '/') || str_contains($relative, '.')) {
            $details[] = rtrim($relative, '/');
        }

        $basename = basename($relative);

        if (str_contains($basename, '.')) {
            $details[] = $basename;
        }

        return $details;
    }

    /**
     * Path dan nama cookie dari raw evidence (pemeriksaan bawaan dan Nuclei).
     *
     * @param  array<string, mixed>  $raw
     * @return list<string>
     */
    private static function rawDetails(array $raw): array
    {
        $details = is_string($raw['path'] ?? null) ? self::pathDetails($raw['path']) : [];

        foreach ($raw['cookies'] ?? [] as $cookie) {
            if (is_string($cookie['name'] ?? null)) {
                $details[] = $cookie['name'];
            }
        }

        // Hasil template cookie Nuclei berupa potongan Set-Cookie
        if (str_starts_with((string) ($raw['template'] ?? ''), 'cookies-')) {
            foreach ($raw['extracted'] ?? [] as $value) {
                $details[] = CookieRules::name((string) $value);
            }
        }

        return $details;
    }
}
