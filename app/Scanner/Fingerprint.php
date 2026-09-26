<?php

namespace App\Scanner;

use App\Scanner\Network\HttpExchange;

/**
 * Pengenalan CDN/WAF dan teknologi dari respons HTTP berdasarkan pola di config/siprika_scanner.php.
 */
class Fingerprint
{
    /**
     * @return list<string>
     */
    public static function cdn(HttpExchange $response): array
    {
        $found = [];

        foreach (config('siprika_scanner.cdn', []) as $name => $rules) {
            if (self::matchesHeaders($response, $rules['headers'] ?? []) !== null) {
                $found[] = $name;
            }
        }

        return $found;
    }

    /**
     * @return list<array{name: string, category: string, version: string|null, source: string}>
     */
    public static function technologies(HttpExchange $response): array
    {
        $found = [];
        $cookieNames = array_map(fn (string $cookie) => CookieRules::name($cookie), $response->headerValues('set-cookie'));
        $generator = self::metaGenerator($response->body);

        foreach (config('siprika_scanner.technologies', []) as $name => $rules) {
            $version = null;
            $matched = false;

            $headerMatch = self::matchesHeaders($response, $rules['headers'] ?? []);

            if ($headerMatch !== null) {
                $matched = true;
                $version = $headerMatch ?: null;
            }

            foreach ($rules['cookies'] ?? [] as $pattern) {
                foreach ($cookieNames as $cookieName) {
                    if (preg_match($pattern, $cookieName)) {
                        $matched = true;
                    }
                }
            }

            foreach ($rules['html'] ?? [] as $pattern) {
                if (preg_match($pattern, $response->body, $m)) {
                    $matched = true;
                    $version ??= ($m[1] ?? '') !== '' ? $m[1] : null;
                }
            }

            if (isset($rules['meta_generator']) && $generator !== null && preg_match($rules['meta_generator'], $generator, $m)) {
                $matched = true;
                $version = ($m[1] ?? null) ?: $version;
            }

            if ($matched) {
                $found[] = ['name' => $name, 'category' => $rules['category'], 'version' => $version, 'source' => 'internal'];
            }
        }

        return $found;
    }

    /**
     * Daftar teknologi untuk ringkasan, contoh: "WordPress 6.4.2, jQuery 3.7.1, Nginx".
     *
     * @param  list<array{name: string, version: string|null}>  $technologies
     */
    public static function describe(array $technologies): string
    {
        return implode(', ', array_map(fn (array $technology) => $technology['name'].($technology['version'] ? " {$technology['version']}" : ''), $technologies));
    }

    /**
     * Mengembalikan versi (string, bisa kosong) jika salah satu header cocok, null jika tidak ada yang cocok.
     *
     * @param  array<string, string|null>  $rules  nama header => regex (null = cukup ada)
     */
    private static function matchesHeaders(HttpExchange $response, array $rules): ?string
    {
        foreach ($rules as $header => $pattern) {
            $value = $response->header($header);

            if ($value === null) {
                continue;
            }

            if ($pattern === null) {
                return '';
            }

            if (preg_match($pattern, $value, $m)) {
                return $m[1] ?? '';
            }
        }

        return null;
    }

    public static function metaGenerator(string $html): ?string
    {
        if (preg_match('/<meta[^>]+name\s*=\s*["\']generator["\'][^>]*content\s*=\s*["\']([^"\']+)["\']/i', $html, $m)
            || preg_match('/<meta[^>]+content\s*=\s*["\']([^"\']+)["\'][^>]*name\s*=\s*["\']generator["\']/i', $html, $m)) {
            return trim($m[1]);
        }

        return null;
    }

    /**
     * Isi atribut content dari tag meta http-equiv atau name tertentu.
     */
    public static function metaContent(string $html, string $attribute, string $value): ?string
    {
        $quoted = preg_quote($value, '/');

        foreach ([
            '/<meta[^>]+'.$attribute.'\s*=\s*["\']?'.$quoted.'["\']?[^>]*content\s*=\s*"([^"]*)"/i',
            '/<meta[^>]+'.$attribute.'\s*=\s*["\']?'.$quoted.'["\']?[^>]*content\s*=\s*\'([^\']*)\'/i',
            '/<meta[^>]+content\s*=\s*"([^"]*)"[^>]*'.$attribute.'\s*=\s*["\']?'.$quoted.'["\']?/i',
            '/<meta[^>]+content\s*=\s*\'([^\']*)\'[^>]*'.$attribute.'\s*=\s*["\']?'.$quoted.'["\']?/i',
        ] as $pattern) {
            if (preg_match($pattern, $html, $m)) {
                return html_entity_decode($m[1], ENT_QUOTES | ENT_HTML5, 'UTF-8');
            }
        }

        return null;
    }

    /**
     * Apakah respons berupa halaman blokir WAF/CDN, bukan website aslinya.
     */
    public static function isWafBlockPage(HttpExchange $response): bool
    {
        if (! in_array($response->status, config('siprika_scanner.waf_block_statuses', []), true)) {
            return false;
        }

        if (self::cdn($response) !== []) {
            return true;
        }

        foreach (config('siprika_scanner.waf_block_patterns', []) as $pattern) {
            if (preg_match($pattern, $response->body)) {
                return true;
            }
        }

        return false;
    }
}
