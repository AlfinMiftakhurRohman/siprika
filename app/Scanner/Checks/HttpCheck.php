<?php

namespace App\Scanner\Checks;

use App\Enums\ObservationStatus;
use App\Scanner\Data\FindingData;
use App\Scanner\Fingerprint;
use App\Scanner\Network\HttpExchange;
use App\Scanner\Network\HttpFailure;
use App\Scanner\ScanContext;

/**
 * HTTP status, redirect, HTTPS, title, server, dan CDN/WAF.
 */
class HttpCheck implements Check
{
    public function key(): string
    {
        return 'http-info';
    }

    public function label(): string
    {
        return 'Informasi HTTP';
    }

    public function run(ScanContext $context): void
    {
        $host = $context->host();
        $entryIsHttps = str_starts_with($context->url(), 'https://');

        [$entry, $entryError] = $this->fetch($context, $context->url());
        [$https, $httpsError] = $entryIsHttps ? [$entry, $entryError] : $this->fetch($context, "https://{$host}/");
        [$http, $httpError] = $entryIsHttps ? $this->fetch($context, "http://{$host}/") : [$entry, $entryError];

        $homepage = $entry ?? $https ?? $http;

        if ($homepage === null) {
            $message = 'Website tidak dapat diakses: '.($entryError?->kindLabel() ?? 'kesalahan jaringan').' ('.mb_substr((string) $entryError?->getMessage(), 0, 200).').';
            $context->observe('http-status', 'HTTP Status / Redirect', 'internal', ObservationStatus::Error, $message);
            $context->abort($message);
        }

        $context->homepage = $homepage;
        $context->wafBlocked = Fingerprint::isWafBlockPage($homepage);

        $this->observeStatus($context, $homepage, $entry === null ? $entryError : null);
        $this->observeHttps($context, $https, $httpsError, $http);
        $this->observeRedirect($context, $http, $httpError);
        $this->observeInfo($context, $homepage);
    }

    /**
     * @return array{0: HttpExchange|null, 1: HttpFailure|null}
     */
    private function fetch(ScanContext $context, string $url): array
    {
        try {
            return [$context->http->get($url), null];
        } catch (HttpFailure $e) {
            return [null, $e];
        }
    }

    private function observeStatus(ScanContext $context, HttpExchange $homepage, ?HttpFailure $entryError): void
    {
        $summary = "Status {$homepage->status} pada {$homepage->url}";

        if (count($homepage->chain) > 0) {
            $summary .= ' setelah '.count($homepage->chain).' redirect';
        }

        $summary .= '.';

        if ($entryError !== null) {
            $summary .= " URL target gagal diakses ({$entryError->kindLabel()}), dipakai respons alternatif.";
        }

        if ($homepage->stoppedReason !== null) {
            $summary .= ' '.$homepage->stoppedReason;
        }

        if ($context->wafBlocked) {
            $summary .= ' Respons terdeteksi sebagai halaman blokir WAF/CDN, pemeriksaan header dan cookie tidak dapat dinilai.'
                .' Agar dapat dinilai, tambahkan pengecualian (allowlist) untuk User-Agent atau IP SIPRIKA di pengaturan WAF/CDN.';
        }

        $context->overview['waf_blocked'] = $context->wafBlocked;
        $context->overview['final_url'] = $homepage->url;
        $context->overview['http_status'] = $homepage->status;
        $context->overview['redirect_chain'] = $homepage->redirectSummary();

        $context->observe('http-status', 'HTTP Status / Redirect', 'internal', ObservationStatus::Info, $summary, [
            'final_url' => $homepage->url,
            'status' => $homepage->status,
            'chain' => $homepage->redirectSummary(),
            'stopped_reason' => $homepage->stoppedReason,
            'waf_blocked' => $context->wafBlocked,
        ]);
    }

    private function observeHttps(ScanContext $context, ?HttpExchange $https, ?HttpFailure $error, ?HttpExchange $http): void
    {
        if ($https !== null) {
            $context->httpsAvailable = true;
            $context->httpsResponse = $https;
            $context->overview['https'] = true;
            $context->observe('https', 'HTTPS', 'internal', ObservationStatus::Pass, "HTTPS merespons dengan status {$https->status}.");

            return;
        }

        $context->httpsFailure = $error;
        $context->overview['https'] = false;
        $refused = in_array($error?->kind, [HttpFailure::REFUSED, HttpFailure::TLS], true);

        // no-https hanya jika port 443 menolak/handshake gagal sementara http:// merespons normal
        if ($refused && $http !== null && $http->status < 500) {
            $detail = "Port 443 {$error->kindLabel()}, sementara http:// merespons status {$http->status}.";
            $context->observe('https', 'HTTPS', 'internal', ObservationStatus::Fail, $detail, ['error' => $error->getMessage()]);
            $context->addFinding(new FindingData('no-https', 'internal', $detail, "https://{$context->host()}/", ['error' => $error->getMessage()]));

            return;
        }

        $context->observe('https', 'HTTPS', 'internal', ObservationStatus::Error, 'HTTPS tidak dapat diperiksa: '.($error?->kindLabel() ?? 'kesalahan').'.', ['error' => $error?->getMessage()]);
    }

    private function observeRedirect(ScanContext $context, ?HttpExchange $http, ?HttpFailure $error): void
    {
        $label = 'Redirect HTTP ke HTTPS';

        if ($http === null) {
            if ($error?->kind === HttpFailure::REFUSED) {
                $context->observe('http-redirect', $label, 'internal', ObservationStatus::NotApplicable, 'Port 80 tertutup, tidak ada layanan HTTP tanpa enkripsi.');
            } else {
                $context->observe('http-redirect', $label, 'internal', ObservationStatus::Error, 'http:// tidak dapat diperiksa: '.($error?->kindLabel() ?? 'kesalahan').'.', ['error' => $error?->getMessage()]);
            }

            return;
        }

        $chain = $http->redirectSummary();
        $redirectsToHttps = $http->isHttps()
            || ($http->isRedirect() && str_starts_with(strtolower((string) $http->header('location')), 'https://'));

        if ($redirectsToHttps) {
            $context->observe('http-redirect', $label, 'internal', ObservationStatus::Pass, 'http:// dialihkan ke HTTPS.', ['chain' => $chain]);

            return;
        }

        if ($http->status >= 200 && $http->status < 300) {
            $detail = "http://{$context->host()}/ merespons status {$http->status} tanpa redirect ke https://.";
            $context->observe('http-redirect', $label, 'internal', ObservationStatus::Fail, $detail, ['chain' => $chain]);
            $context->addFinding(new FindingData('http-not-redirected', 'internal', $detail, $http->url, ['chain' => $chain]));

            return;
        }

        $context->observe('http-redirect', $label, 'internal', ObservationStatus::Info, "http:// merespons status {$http->status} tanpa redirect ke HTTPS.", ['chain' => $chain]);
    }

    private function observeInfo(ScanContext $context, HttpExchange $homepage): void
    {
        $title = $homepage->title();
        $server = $homepage->header('server');
        $poweredBy = $homepage->header('x-powered-by');
        $cdn = Fingerprint::cdn($homepage);

        $context->overview['title'] = $title;
        $context->overview['web_server'] = $server;
        $context->overview['powered_by'] = $poweredBy;
        $context->overview['cdn'] = $cdn;

        $parts = array_filter([
            $title !== null ? "Title: {$title}" : null,
            $server !== null ? "Server: {$server}" : null,
            $poweredBy !== null ? "X-Powered-By: {$poweredBy}" : null,
            $cdn !== [] ? 'CDN/WAF: '.implode(', ', $cdn) : null,
        ]);

        $context->observe('http-info', 'Title / Server / CDN', 'internal', ObservationStatus::Info, $parts === [] ? 'Tidak ada informasi tambahan.' : implode('; ', $parts).'.', [
            'title' => $title,
            'server' => $server,
            'x_powered_by' => $poweredBy,
            'cdn' => $cdn,
        ]);
    }
}
