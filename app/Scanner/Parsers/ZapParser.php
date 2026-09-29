<?php

namespace App\Scanner\Parsers;

use App\Scanner\CookieRules;
use App\Scanner\Data\FindingData;
use App\Scanner\Evidence;

/**
 * Mengubah alert passive scan OWASP ZAP menjadi finding katalog (config siprika_scanner.zap_map)
 * dan daftar alert untuk Coverage. Alert di luar katalog tidak menjadi finding.
 */
class ZapParser
{
    /**
     * Aturan cookie ZAP dinilai dengan aturan insecure-cookie yang sama dengan CookieCheck (bagian 23.1):
     * semua cookie wajib Secure, HttpOnly dan SameSite hanya untuk cookie sesi.
     */
    private const COOKIE_RULES = [
        '10011' => 'tanpa Secure',
        '10010' => 'tanpa HttpOnly',
        '10054' => 'tanpa SameSite',
    ];

    /**
     * Header teknologi hanya temuan jika memuat nomor versi, contoh "PHP/8.1.2" (bagian 23.1).
     */
    private const VERSION_RULES = ['10036', '10037', '10061'];

    /**
     * @param  list<array<string, mixed>>  $alerts  hasil API alert/view/alerts
     * @return array{findings: list<FindingData>, alerts: list<array{plugin: string, ref: string, name: string, risk: string, url: string, param: string, evidence: string}>}
     */
    public static function parse(array $alerts): array
    {
        $parsed = ['findings' => [], 'alerts' => []];

        foreach ($alerts as $alert) {
            $item = [
                'plugin' => (string) ($alert['pluginId'] ?? ''),
                'ref' => (string) ($alert['alertRef'] ?? $alert['pluginId'] ?? ''),
                'name' => (string) ($alert['alert'] ?? $alert['name'] ?? ''),
                'risk' => (string) ($alert['risk'] ?? ''),
                'url' => (string) ($alert['url'] ?? ''),
                'param' => (string) ($alert['param'] ?? ''),
                'evidence' => Evidence::maskSecrets((string) ($alert['evidence'] ?? '')),
            ];

            $parsed['alerts'][] = $item;
            $finding = self::finding($item);

            if ($finding !== null) {
                $parsed['findings'][] = $finding;
            }
        }

        return $parsed;
    }

    /**
     * @param  array{plugin: string, ref: string, name: string, risk: string, url: string, param: string, evidence: string}  $alert
     */
    private static function finding(array $alert): ?FindingData
    {
        $map = config('siprika_scanner.zap_map', []);
        $key = $map[$alert['ref']] ?? $map[$alert['plugin']] ?? null;

        if ($key === null) {
            return null;
        }

        $raw = ['plugin' => $alert['plugin'], 'alert_ref' => $alert['ref'], 'alert' => $alert['name'], 'param' => $alert['param'], 'evidence' => $alert['evidence']];
        $detail = "{$alert['name']} (OWASP ZAP)";

        if (isset(self::COOKIE_RULES[$alert['plugin']])) {
            $name = $alert['param'];
            $applies = $alert['plugin'] === '10011' || (CookieRules::isSession($name) && ($alert['plugin'] !== '10010' || ! CookieRules::isJsReadable($name)));

            if ($name === '' || ! $applies) {
                return null;
            }

            $detail = "cookie {$name} ".self::COOKIE_RULES[$alert['plugin']].' (OWASP ZAP)';
        }

        if (in_array($alert['plugin'], self::VERSION_RULES, true)) {
            if (! preg_match('/\d+\.\d+/', $alert['evidence'])) {
                return null;
            }

            $detail = "versi software terlihat pada header: {$alert['evidence']} (OWASP ZAP)";
        }

        return new FindingData($key, 'zap', $detail, $alert['url'] !== '' ? $alert['url'] : null, $raw);
    }
}
