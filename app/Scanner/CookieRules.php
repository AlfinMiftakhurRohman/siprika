<?php

namespace App\Scanner;

/**
 * Aturan cookie untuk kunci insecure-cookie (bagian 23.1), dipakai pemeriksaan bawaan dan hasil Nuclei.
 * Daftar nama cookie sesi dan cookie yang dibaca JavaScript ada di config/siprika_scanner.php.
 */
class CookieRules
{
    /**
     * Nama cookie dari header Set-Cookie, contoh "PHPSESSID=abc; path=/" menjadi "PHPSESSID".
     */
    public static function name(string $setCookie): string
    {
        return trim(explode('=', explode(';', $setCookie, 2)[0], 2)[0]);
    }

    /**
     * Nilai cookie tidak disimpan, hanya nama dan atributnya.
     *
     * @return array{name: string, secure: bool, httponly: bool, samesite: string|null, session: bool, js_readable: bool}
     */
    public static function parse(string $setCookie): array
    {
        $name = self::name($setCookie);
        $attributes = [];

        foreach (array_slice(explode(';', $setCookie), 1) as $part) {
            [$key, $value] = array_pad(explode('=', trim($part), 2), 2, null);
            $attributes[strtolower(trim((string) $key))] = $value !== null ? trim($value) : true;
        }

        $samesite = $attributes['samesite'] ?? null;

        return [
            'name' => $name,
            'secure' => isset($attributes['secure']),
            'httponly' => isset($attributes['httponly']),
            'samesite' => is_string($samesite) && $samesite !== '' ? $samesite : null,
            'session' => self::isSession($name),
            'js_readable' => self::isJsReadable($name),
        ];
    }

    /**
     * Cookie sesi dikenali dari nama, prefix, atau akhiran (contoh laravel_session, wordpress_logged_in_xxx).
     */
    public static function isSession(string $name): bool
    {
        $name = strtolower($name);

        if (in_array($name, config('siprika_scanner.session_cookies', []), true)) {
            return true;
        }

        foreach (config('siprika_scanner.session_cookie_prefixes', []) as $prefix) {
            if (str_starts_with($name, $prefix)) {
                return true;
            }
        }

        foreach (config('siprika_scanner.session_cookie_suffixes', []) as $suffix) {
            if (str_ends_with($name, $suffix)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Cookie yang memang dibaca JavaScript (contoh XSRF-TOKEN) tidak diperiksa HttpOnly.
     */
    public static function isJsReadable(string $name): bool
    {
        return in_array(strtolower($name), config('siprika_scanner.js_readable_cookies', []), true);
    }
}
