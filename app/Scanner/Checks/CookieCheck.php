<?php

namespace App\Scanner\Checks;

use App\Enums\ObservationStatus;
use App\Scanner\CookieRules;
use App\Scanner\Data\FindingData;
use App\Scanner\Network\HttpExchange;
use App\Scanner\ScanContext;

/**
 * Atribut keamanan cookie pada respons HTTPS (bagian 23.1, kunci insecure-cookie).
 */
class CookieCheck implements Check
{
    public function key(): string
    {
        return 'cookie-security';
    }

    public function label(): string
    {
        return 'Cookie Security';
    }

    public function run(ScanContext $context): void
    {
        $label = 'Cookie Security';

        if ($context->wafBlocked) {
            $context->observe('cookie-security', $label, 'internal', ObservationStatus::NotAssessed, 'Respons berupa halaman blokir WAF/CDN, bukan website aslinya.');

            return;
        }

        $responses = $this->httpsResponses($context);

        if ($responses === []) {
            $context->observe('cookie-security', $label, 'internal', ObservationStatus::NotApplicable, 'Tidak ada respons HTTPS untuk diperiksa.');

            return;
        }

        $cookies = [];

        foreach ($responses as $response) {
            foreach ($response->headerValues('set-cookie') as $header) {
                $cookie = CookieRules::parse($header);
                $cookie['url'] = $response->url;
                $cookies[$cookie['name']] = $cookie;
            }
        }

        if ($cookies === []) {
            $context->observe('cookie-security', $label, 'internal', ObservationStatus::Pass, 'Halaman utama tidak memasang cookie.');

            return;
        }

        $issues = [];

        foreach ($cookies as $cookie) {
            $problems = [];

            if (! $cookie['secure']) {
                $problems[] = 'tanpa Secure';
            }

            if ($cookie['session'] && ! $cookie['httponly'] && ! $cookie['js_readable']) {
                $problems[] = 'tanpa HttpOnly';
            }

            if ($cookie['session'] && $cookie['samesite'] === null) {
                $problems[] = 'tanpa SameSite';
            }

            if ($problems !== []) {
                $issues[] = "cookie {$cookie['name']} ".implode(', ', $problems);
            }
        }

        $raw = ['cookies' => array_values(array_map(fn ($c) => array_diff_key($c, ['url' => true]), $cookies))];

        if ($issues === []) {
            $context->observe('cookie-security', $label, 'internal', ObservationStatus::Pass, count($cookies).' cookie memiliki atribut keamanan yang sesuai.', $raw);

            return;
        }

        $detail = implode('; ', $issues);
        $context->observe('cookie-security', $label, 'internal', ObservationStatus::Fail, ucfirst($detail).'.', $raw);
        $context->addFinding(new FindingData('insecure-cookie', 'internal', $detail, $context->homepage?->url, $raw));
    }

    /**
     * @return list<HttpExchange>
     */
    private function httpsResponses(ScanContext $context): array
    {
        $responses = [];

        foreach ([$context->homepage, $context->httpsResponse] as $exchange) {
            foreach ($exchange?->allResponses() ?? [] as $response) {
                if ($response->isHttps()) {
                    $responses[$response->url.'#'.$response->status] = $response;
                }
            }
        }

        return array_values($responses);
    }
}
