<?php

namespace App\Scanner\Parsers;

/**
 * Mengubah isi file JSON WhatWeb (--log-json) menjadi daftar teknologi.
 */
class WhatWebParser
{
    /**
     * Plugin WhatWeb yang bukan nama teknologi.
     */
    private const IGNORED_PLUGINS = [
        'Country', 'IP', 'Title', 'HTTPServer', 'Script', 'HTML5', 'UncommonHeaders', 'X-UA-Compatible',
        'Meta-Author', 'Email', 'Cookies', 'PasswordField', 'RedirectLocation', 'Strict-Transport-Security',
        'X-Frame-Options', 'X-XSS-Protection', 'HttpOnly', 'Frame', 'Via-Proxy', 'Content-Language',
        'Open-Graph-Protocol', 'Meta-Refresh-Redirect', 'Access-Control-Allow-Methods', 'Allow', 'Object',
        'X-Powered-By', 'PoweredBy', 'Content-Security-Policy', 'X-Content-Type-Options', 'Referrer-Policy',
    ];

    /**
     * @param  list<array<string, mixed>>  $items
     * @return list<array{name: string, category: string, version: string|null, source: string}>
     */
    public static function parse(array $items): array
    {
        $technologies = [];

        foreach ($items as $item) {
            foreach (($item['plugins'] ?? []) as $name => $plugin) {
                if (in_array($name, self::IGNORED_PLUGINS, true) || isset($technologies[$name])) {
                    continue;
                }

                $version = $plugin['version'][0] ?? null;
                $technologies[$name] = ['name' => (string) $name, 'category' => 'Teknologi (WhatWeb)', 'version' => $version !== null ? (string) $version : null, 'source' => 'whatweb'];
            }
        }

        return array_values($technologies);
    }
}
