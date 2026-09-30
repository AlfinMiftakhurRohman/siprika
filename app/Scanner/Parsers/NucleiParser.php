<?php

namespace App\Scanner\Parsers;

use App\Enums\Severity;
use App\Scanner\CookieRules;
use App\Scanner\Data\FindingData;
use App\Scanner\Evidence;
use Illuminate\Support\Str;

/**
 * Mengubah output JSONL Nuclei menjadi finding, teknologi, dan daftar hasil untuk Coverage.
 * Template dipetakan ke kunci katalog lewat config siprika_scanner.nuclei_map (bagian 23).
 */
class NucleiParser
{
    /** Template cookie yang dinilai dengan aturan insecure-cookie */
    public const COOKIE_TEMPLATES = ['cookies-without-secure', 'cookies-without-httponly'];

    /**
     * Kunci katalog yang dapat dihasilkan daftar template, contoh dari "nuclei -tl". Template exposure
     * dikenali dari foldernya (http/exposures), sama seperti tag exposure pada peta exposure.
     *
     * @param  list<string>  $paths  path template relatif, contoh ssl/weak-cipher-suites.yaml
     * @return list<string>
     */
    public static function keysForTemplates(array $paths): array
    {
        $byTemplate = [];

        foreach (config('siprika_scanner.nuclei_map', []) as $id => $key) {
            if ($key !== null) {
                $byTemplate[explode(':', $id)[0]][] = $key;
            }
        }

        foreach (self::COOKIE_TEMPLATES as $id) {
            $byTemplate[$id][] = 'insecure-cookie';
        }

        $keys = [];

        foreach ($paths as $path) {
            $path = str_replace('\\', '/', trim($path));
            array_push($keys, ...($byTemplate[basename($path, '.yaml')] ?? []));

            if (str_contains($path, '/exposures/')) {
                $keys[] = 'exposed-sensitive-file';
            }
        }

        return array_values(array_unique($keys));
    }

    /**
     * @return array{findings: list<FindingData>, technologies: list<array{name: string, category: string, version: string|null, source: string}>, results: list<array<string, mixed>>}
     */
    public static function parse(string $output): array
    {
        $parsed = ['findings' => [], 'technologies' => [], 'results' => []];

        foreach (preg_split('/\R/', $output) as $line) {
            $item = json_decode(trim($line), true);

            if (! is_array($item) || ! isset($item['template-id'])) {
                continue;
            }

            $result = self::normalize($item);
            $parsed['results'][] = ['template' => $result['full_id'], 'severity' => $result['severity']->value, 'matched_at' => $result['matched_at'], 'name' => $result['name']];

            // Template heuristik yang sering keliru hanya dicatat di hasil mentah
            if (in_array($result['template_id'], config('siprika_scanner.nuclei_raw_only', []), true)) {
                continue;
            }

            if (self::isTechnology($result)) {
                $parsed['technologies'][] = ['name' => self::technologyName($result), 'category' => 'Teknologi (Nuclei)', 'version' => null, 'source' => 'nuclei'];

                continue;
            }

            $finding = self::finding($result);

            if ($finding !== null) {
                $parsed['findings'][] = $finding;
            }
        }

        return $parsed;
    }

    /**
     * Finding Nuclei di luar katalog dengan severity info hanya informasi, bukan kerawanan (bagian 24.4).
     */
    public static function isInformational(FindingData $finding): bool
    {
        return str_starts_with($finding->key, 'nuclei:') && Severity::fromLoose($finding->severity) === Severity::Info;
    }

    /**
     * @param  array<string, mixed>  $item  satu baris JSONL Nuclei
     * @return array{template_id: string, matcher: string|null, full_id: string, severity: Severity, tags: list<string>, matched_at: string, name: string, info: array<string, mixed>, extracted: list<string>}
     */
    private static function normalize(array $item): array
    {
        $templateId = (string) $item['template-id'];
        $matcher = isset($item['matcher-name']) ? (string) $item['matcher-name'] : null;
        $info = $item['info'] ?? [];
        $tags = is_array($info['tags'] ?? null) ? $info['tags'] : array_filter(array_map('trim', explode(',', (string) ($info['tags'] ?? ''))));

        return [
            'template_id' => $templateId,
            'matcher' => $matcher,
            'full_id' => $matcher !== null ? "{$templateId}:{$matcher}" : $templateId,
            'severity' => Severity::fromLoose($info['severity'] ?? 'info'),
            'tags' => array_values($tags),
            'matched_at' => (string) ($item['matched-at'] ?? $item['host'] ?? ''),
            'name' => (string) ($info['name'] ?? $templateId),
            'info' => $info,
            'extracted' => array_slice(array_map(fn ($value) => Evidence::maskSecrets((string) $value), (array) ($item['extracted-results'] ?? [])), 0, 5),
        ];
    }

    /**
     * Deteksi teknologi (tag tech, severity info) bukan temuan, kecuali template dipetakan ke katalog.
     *
     * @param  array<string, mixed>  $result
     */
    private static function isTechnology(array $result): bool
    {
        return in_array('tech', $result['tags'], true)
            && $result['severity'] === Severity::Info
            && self::mapEntry($result) === null;
    }

    /**
     * Nama teknologi dari matcher (contoh "font-awesome" menjadi "Font Awesome"), atau nama template.
     *
     * @param  array<string, mixed>  $result
     */
    private static function technologyName(array $result): string
    {
        $name = $result['matcher'] ?? $result['name'];

        // Slug huruf kecil dari matcher dibuat mudah dibaca; nama dengan huruf besar dibiarkan
        return $name === strtolower($name) ? ucwords(str_replace(['-', '_'], ' ', $name)) : $name;
    }

    /**
     * @param  array<string, mixed>  $result
     */
    private static function finding(array $result): ?FindingData
    {
        $detail = "template Nuclei {$result['full_id']} cocok pada {$result['matched_at']}";
        $raw = ['template' => $result['full_id'], 'name' => $result['name'], 'severity' => $result['severity']->value, 'matched_at' => $result['matched_at'], 'extracted' => $result['extracted']];

        // Cookie yang melanggar aturan insecure-cookie menjadi temuan katalog; sisanya tetap informasi (bagian 24.4)
        $cookie = self::cookieFinding($result, $raw);

        if ($cookie !== null) {
            return $cookie;
        }

        $mapEntry = self::mapEntry($result);

        // Nilai null di peta berarti hasil template hanya informasi, bukan temuan
        if ($mapEntry !== null && $mapEntry['key'] === null) {
            return null;
        }

        $key = $mapEntry['key'] ?? self::exposureKey($result);

        if (in_array($key, config('siprika_scanner.https_only_findings', []), true) && ! str_starts_with(strtolower($result['matched_at']), 'https://')) {
            return null;
        }

        if ($key === 'tls-weak-cipher') {
            if (! self::hasWeakCipher($result['extracted'])) {
                return null;
            }

            $detail .= $result['extracted'] !== [] ? ' ('.trim(implode(', ', $result['extracted']), '[]').')' : '';
        }

        if ($key === 'exposed-sensitive-file') {
            $raw['snippet'] = Evidence::snippet(implode(' ', $result['extracted']), 'env');
        }

        return $key !== null
            ? new FindingData($key, 'nuclei', $detail, $result['matched_at'], $raw)
            : self::uncatalogued($result, $detail, $raw);
    }

    /**
     * Bukti Nuclei yang tersimpan masih sesuai aturan saat ini. Dipakai siprika:recalculate supaya aturan baru
     * (contoh cipher lemah) juga berlaku untuk hasil pemeriksaan lama tanpa memindai ulang.
     *
     * @param  array<string, mixed>  $raw  raw bukti yang disimpan finding()
     */
    public static function acceptsStoredEvidence(string $key, array $raw): bool
    {
        if (in_array(substr($key, strlen('nuclei:')), config('siprika_scanner.nuclei_raw_only', []), true) && str_starts_with($key, 'nuclei:')) {
            return false;
        }

        return $key !== 'tls-weak-cipher' || self::hasWeakCipher(array_values(array_map('strval', (array) ($raw['extracted'] ?? []))));
    }

    /**
     * Cipher hasil Nuclei (contoh "[tls10 TLS_RSA_WITH_3DES_EDE_CBC_SHA]") termasuk kategori lemah katalog.
     * Tanpa nama cipher hasil tetap dianggap lemah supaya cipher lemah tidak terlewat.
     *
     * @param  list<string>  $extracted
     */
    private static function hasWeakCipher(array $extracted): bool
    {
        if ($extracted === []) {
            return true;
        }

        return Str::contains(implode(' ', $extracted), config('siprika_scanner.nuclei_weak_cipher_patterns', []));
    }

    /**
     * Entri config siprika_scanner.nuclei_map untuk "template-id:matcher" atau "template-id", null jika tidak ada.
     *
     * @param  array<string, mixed>  $result
     * @return array{key: string|null}|null
     */
    private static function mapEntry(array $result): ?array
    {
        $map = config('siprika_scanner.nuclei_map', []);

        foreach ([$result['full_id'], $result['template_id']] as $id) {
            if (array_key_exists($id, $map)) {
                return ['key' => $map[$id]];
            }
        }

        return null;
    }

    /**
     * Template exposure dengan severity minimal low menjadi exposed-sensitive-file.
     *
     * @param  array<string, mixed>  $result
     */
    private static function exposureKey(array $result): ?string
    {
        $minimum = Severity::fromLoose((string) config('siprika_scanner.nuclei_exposure_min_severity', 'medium'));
        $exposure = $result['severity']->rank() >= max(1, $minimum->rank())
            && array_intersect($result['tags'], config('siprika_scanner.nuclei_exposure_tags', [])) !== [];

        return $exposure ? 'exposed-sensitive-file' : null;
    }

    /**
     * Template cookie dinilai dengan aturan insecure-cookie yang sama dengan CookieCheck (bagian 23.1):
     * semua cookie wajib Secure, HttpOnly hanya untuk cookie sesi yang tidak memang dibaca JavaScript.
     * Template lain (contoh SameSite=Strict) tetap informasi karena SameSite=Lax sudah memenuhi aturan.
     *
     * @param  array<string, mixed>  $result
     * @param  array<string, mixed>  $raw
     */
    private static function cookieFinding(array $result, array $raw): ?FindingData
    {
        $names = array_values(array_unique(array_filter(array_map(fn (string $value) => CookieRules::name($value), $result['extracted']))));

        [$names, $problem] = match ($result['template_id']) {
            'cookies-without-secure' => [$names, 'tanpa Secure'],
            'cookies-without-httponly' => [array_values(array_filter($names, fn (string $name) => CookieRules::isSession($name) && ! CookieRules::isJsReadable($name))), 'tanpa HttpOnly'],
            default => [[], null],
        };

        if ($names === []) {
            return null;
        }

        return new FindingData('insecure-cookie', 'nuclei', 'cookie '.implode(', ', $names)." {$problem} (Nuclei)", $result['matched_at'], $raw);
    }

    /**
     * Finding di luar katalog memakai kunci nuclei:<template-id> (bagian 24.4).
     *
     * @param  array<string, mixed>  $result
     * @param  array<string, mixed>  $raw
     */
    private static function uncatalogued(array $result, string $detail, array $raw): FindingData
    {
        $info = $result['info'];
        $classification = $info['classification'] ?? [];
        $cve = is_array($classification['cve-id'] ?? null) ? ($classification['cve-id'][0] ?? null) : ($classification['cve-id'] ?? null);
        $cvss = isset($classification['cvss-score']) && is_numeric($classification['cvss-score']) ? (float) $classification['cvss-score'] : null;

        return new FindingData(
            key: 'nuclei:'.$result['template_id'],
            source: 'nuclei',
            detail: $detail,
            endpoint: $result['matched_at'],
            raw: $raw,
            title: $result['name'],
            severity: $result['severity']->value,
            description: isset($info['description']) ? trim((string) $info['description']) : null,
            recommendation: isset($info['remediation']) ? trim((string) $info['remediation']) : null,
            cve: $cve !== null ? strtoupper((string) $cve) : null,
            cvss: $cvss,
        );
    }
}
