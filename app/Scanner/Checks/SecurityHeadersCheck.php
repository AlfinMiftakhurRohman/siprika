<?php

namespace App\Scanner\Checks;

use App\Enums\ObservationStatus;
use App\Scanner\Data\FindingData;
use App\Scanner\Fingerprint;
use App\Scanner\Network\HttpExchange;
use App\Scanner\ScanContext;

/**
 * Pemeriksaan header keamanan pada respons halaman utama final (bagian 23.1).
 */
class SecurityHeadersCheck implements Check
{
    private const LABELS = [
        'header-hsts' => 'HSTS',
        'header-csp' => 'Content-Security-Policy',
        'header-x-frame-options' => 'X-Frame-Options',
        'header-x-content-type-options' => 'X-Content-Type-Options',
        'header-referrer-policy' => 'Referrer-Policy',
        'server-version' => 'Versi Server',
    ];

    public function key(): string
    {
        return 'security-headers';
    }

    public function label(): string
    {
        return 'Security Headers';
    }

    public function run(ScanContext $context): void
    {
        $response = $context->homepage;
        $reason = match (true) {
            $response === null => 'Halaman utama tidak dapat diakses.',
            $context->wafBlocked => 'Respons berupa halaman blokir WAF/CDN, bukan website aslinya.',
            // Bagian 22.11: respons redirect yang tidak diikuti bukan halaman website
            $response->isRedirectStopped() => $response->stoppedRedirectNote(),
            default => null,
        };

        if ($reason !== null) {
            foreach (self::LABELS as $key => $label) {
                $context->observe($key, $label, 'internal', ObservationStatus::NotAssessed, $reason);
            }

            return;
        }

        $this->checkHsts($context, $response);
        $this->checkCsp($context, $response);
        $this->checkFrameOptions($context, $response);
        $this->checkContentTypeOptions($context, $response);
        $this->checkReferrerPolicy($context, $response);
        $this->checkServerVersion($context, $response);
    }

    private function checkHsts(ScanContext $context, HttpExchange $response): void
    {
        // HSTS hanya dinilai pada respons HTTPS; jika halaman utama final HTTP, pakai respons https:// jika ada
        if (! $response->isHttps()) {
            $https = $context->httpsResponse;

            if ($https?->isRedirectStopped()) {
                $context->observe('header-hsts', self::LABELS['header-hsts'], 'internal', ObservationStatus::NotAssessed, $https->stoppedRedirectNote());

                return;
            }

            // Respons HTTPS terakhir, termasuk respons https:// yang mengalihkan ke http://
            $response = collect($https?->allResponses() ?? [])->last(fn (HttpExchange $r) => $r->isHttps());
        }

        if ($response === null) {
            $context->observe('header-hsts', self::LABELS['header-hsts'], 'internal', ...$context->httpsMissingStatus('HSTS'));

            return;
        }

        $value = $response->headerValues('strict-transport-security')[0] ?? null;
        $maxAge = $value !== null && preg_match('/max-age\s*=\s*"?(\d+)"?/i', $value, $m) ? (int) $m[1] : null;
        $raw = ['strict-transport-security' => $value, 'max_age' => $maxAge];

        if ($value === null || $maxAge === null || $maxAge === 0) {
            $detail = $value === null
                ? 'header Strict-Transport-Security tidak ditemukan pada respons HTTPS'
                : "header Strict-Transport-Security bernilai \"{$value}\" (max-age tidak efektif)";

            $this->fail($context, 'header-hsts', 'missing-hsts', $detail, $response, $raw);

            return;
        }

        $context->observe('header-hsts', self::LABELS['header-hsts'], 'internal', ObservationStatus::Pass, "Strict-Transport-Security: {$value}", $raw);
    }

    private function checkCsp(ScanContext $context, HttpExchange $response): void
    {
        $header = $response->header('content-security-policy');
        $meta = Fingerprint::metaContent($response->body, 'http-equiv', 'Content-Security-Policy');
        $reportOnly = $response->header('content-security-policy-report-only');
        $raw = ['content-security-policy' => $header, 'meta' => $meta, 'report_only' => $reportOnly];

        if ($header === null && $meta === null) {
            $detail = 'header dan tag meta Content-Security-Policy tidak ditemukan';

            if ($reportOnly !== null) {
                $detail .= ', hanya ada Content-Security-Policy-Report-Only';
            }

            $this->fail($context, 'header-csp', 'missing-csp', $detail, $response, $raw);

            return;
        }

        $context->observe('header-csp', self::LABELS['header-csp'], 'internal', ObservationStatus::Pass, $header !== null ? 'Header Content-Security-Policy ada.' : 'CSP diterapkan melalui tag meta.', $raw);
    }

    private function checkFrameOptions(ScanContext $context, HttpExchange $response): void
    {
        $value = $response->headerValues('x-frame-options')[0] ?? null;
        $csp = (string) $response->header('content-security-policy');
        $validXfo = $value !== null && in_array(strtoupper(trim($value)), ['DENY', 'SAMEORIGIN'], true);
        $frameAncestors = preg_match('/(?:^|;)\s*frame-ancestors\s/i', $csp) === 1;
        $raw = ['x-frame-options' => $value, 'csp_frame_ancestors' => $frameAncestors];

        if (! $validXfo && ! $frameAncestors) {
            $detail = $value === null
                ? 'header X-Frame-Options dan direktif CSP frame-ancestors tidak ditemukan'
                : "header X-Frame-Options bernilai \"{$value}\" dan tidak ada direktif CSP frame-ancestors";

            $this->fail($context, 'header-x-frame-options', 'missing-x-frame-options', $detail, $response, $raw);

            return;
        }

        $context->observe('header-x-frame-options', self::LABELS['header-x-frame-options'], 'internal', ObservationStatus::Pass, $validXfo ? "X-Frame-Options: {$value}" : 'Dilindungi direktif CSP frame-ancestors.', $raw);
    }

    private function checkContentTypeOptions(ScanContext $context, HttpExchange $response): void
    {
        $value = $response->headerValues('x-content-type-options')[0] ?? null;

        if ($value === null || strtolower(trim($value)) !== 'nosniff') {
            $detail = $value === null
                ? 'header X-Content-Type-Options tidak ditemukan'
                : "header X-Content-Type-Options bernilai \"{$value}\", bukan nosniff";

            $this->fail($context, 'header-x-content-type-options', 'missing-x-content-type-options', $detail, $response, ['x-content-type-options' => $value]);

            return;
        }

        $context->observe('header-x-content-type-options', self::LABELS['header-x-content-type-options'], 'internal', ObservationStatus::Pass, 'X-Content-Type-Options: nosniff', ['x-content-type-options' => $value]);
    }

    private function checkReferrerPolicy(ScanContext $context, HttpExchange $response): void
    {
        $header = $response->header('referrer-policy');
        $meta = Fingerprint::metaContent($response->body, 'name', 'referrer');
        $raw = ['referrer-policy' => $header, 'meta' => $meta];

        if ($header === null && $meta === null) {
            $this->fail($context, 'header-referrer-policy', 'missing-referrer-policy', 'header Referrer-Policy dan tag meta referrer tidak ditemukan', $response, $raw);

            return;
        }

        $context->observe('header-referrer-policy', self::LABELS['header-referrer-policy'], 'internal', ObservationStatus::Pass, 'Referrer-Policy: '.($header ?? $meta), $raw);
    }

    private function checkServerVersion(ScanContext $context, HttpExchange $response): void
    {
        $disclosed = [];

        foreach (['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version'] as $name) {
            foreach ($response->headerValues($name) as $value) {
                if (preg_match('/\d+\.\d+/', $value)) {
                    $disclosed[$name] = $value;
                }
            }
        }

        if ($disclosed !== []) {
            $detail = 'versi software terlihat pada header '.implode(', ', array_map(fn ($name, $value) => "{$name}: {$value}", array_keys($disclosed), $disclosed));
            $this->fail($context, 'server-version', 'server-version-disclosure', $detail, $response, $disclosed);

            return;
        }

        $context->observe('server-version', self::LABELS['server-version'], 'internal', ObservationStatus::Pass, 'Header Server dan X-Powered-By tidak menampilkan nomor versi.', [
            'server' => $response->header('server'),
            'x-powered-by' => $response->header('x-powered-by'),
        ]);
    }

    /**
     * @param  array<string, mixed>  $raw
     */
    private function fail(ScanContext $context, string $observationKey, string $findingKey, string $detail, HttpExchange $response, array $raw): void
    {
        $context->observe($observationKey, self::LABELS[$observationKey], 'internal', ObservationStatus::Fail, ucfirst($detail).'.', $raw);
        $context->addFinding(new FindingData($findingKey, 'internal', $detail, $response->url, $raw));
    }
}
