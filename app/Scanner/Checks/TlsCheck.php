<?php

namespace App\Scanner\Checks;

use App\Enums\ObservationStatus;
use App\Scanner\Data\FindingData;
use App\Scanner\Network\HttpFailure;
use App\Scanner\Network\TlsInspector;
use App\Scanner\Network\TlsReport;
use App\Scanner\ScanContext;
use Carbon\CarbonImmutable;

/**
 * Sertifikat, rantai sertifikat, masa berlaku, dan versi protokol TLS.
 */
class TlsCheck implements Check
{
    private const LABELS = [
        'tls-certificate' => 'Sertifikat TLS',
        'tls-chain' => 'Rantai Sertifikat',
        'tls-expiry' => 'Masa Berlaku Sertifikat',
        'tls-protocol' => 'Protokol TLS',
    ];

    public function __construct(private TlsInspector $inspector) {}

    public function key(): string
    {
        return 'tls';
    }

    public function label(): string
    {
        return 'TLS';
    }

    public function run(ScanContext $context): void
    {
        if (! $context->httpsAvailable) {
            $unavailable = in_array($context->httpsFailure?->kind, [HttpFailure::REFUSED, HttpFailure::TLS], true);
            $this->all($context, $unavailable ? ObservationStatus::NotApplicable : ObservationStatus::Error, $unavailable
                ? 'HTTPS tidak tersedia pada website ini.'
                : 'HTTPS tidak dapat diakses: '.($context->httpsFailure?->kindLabel() ?? 'kesalahan').'.');

            return;
        }

        $host = $context->host();
        $ip = (string) $context->primaryIp();
        $port = $context->httpsPort();

        try {
            $report = $this->inspector->inspect($host, $ip, $port);
        } catch (HttpFailure $e) {
            $this->all($context, ObservationStatus::Error, "Koneksi TLS gagal ({$e->kindLabel()}): ".mb_substr($e->getMessage(), 0, 200));

            return;
        }

        $context->tlsReport = $report;
        $endpoint = $context->httpsEndpoint();
        $raw = $report->toArray();

        $invalidReasons = $report->verified ? [] : $this->invalidReasons($report, $host);
        $certificateValid = $report->verified;

        // Sertifikat
        if ($certificateValid) {
            $context->observe('tls-certificate', self::LABELS['tls-certificate'], 'internal', ObservationStatus::Pass, "Sertifikat valid, diterbitkan oleh {$report->issuer}.", $raw);
        } elseif ($invalidReasons !== []) {
            $detail = implode(', ', $invalidReasons);
            $context->observe('tls-certificate', self::LABELS['tls-certificate'], 'internal', ObservationStatus::Fail, ucfirst($detail).'.', $raw);
            $context->addFinding(new FindingData('tls-cert-invalid', 'internal', $detail, $endpoint, $raw + ['openssl_error' => $report->verifyError]));
        } else {
            $context->observe('tls-certificate', self::LABELS['tls-certificate'], 'internal', ObservationStatus::Fail, 'Verifikasi sertifikat gagal: penerbit tidak dikenali.', $raw);
        }

        // Rantai sertifikat
        if (! $certificateValid && $invalidReasons === []) {
            $detail = 'verifikasi gagal karena penerbit sertifikat tidak dikenali'.($report->verifyError ? " ({$report->verifyError})" : '');
            $context->observe('tls-chain', self::LABELS['tls-chain'], 'internal', ObservationStatus::Fail, ucfirst($detail).'.', $raw);
            $context->addFinding(new FindingData('tls-chain-incomplete', 'internal', $detail, $endpoint, $raw));
        } elseif ($certificateValid && $report->chainLength <= 1 && ! $report->selfSigned) {
            $detail = 'server hanya mengirim 1 sertifikat, sertifikat intermediate tidak dikirim';
            $context->observe('tls-chain', self::LABELS['tls-chain'], 'internal', ObservationStatus::Fail, ucfirst($detail).'.', $raw);
            $context->addFinding(new FindingData('tls-chain-incomplete', 'internal', $detail, $endpoint, $raw));
        } elseif ($certificateValid) {
            $context->observe('tls-chain', self::LABELS['tls-chain'], 'internal', ObservationStatus::Pass, "Server mengirim {$report->chainLength} sertifikat.", $raw);
        } else {
            $context->observe('tls-chain', self::LABELS['tls-chain'], 'internal', ObservationStatus::NotApplicable, 'Sertifikat tidak valid, rantai tidak dinilai terpisah.', $raw);
        }

        $this->checkExpiry($context, $report, $certificateValid, $endpoint);
        $this->checkProtocols($context, $host, $ip, $port, $endpoint, $report);

        $context->overview['tls'] = [
            'protocol' => $report->protocol,
            'issuer' => $report->issuer,
            'valid_to' => $report->validTo?->toDateString(),
            'days_left' => $report->validTo ? (int) floor(CarbonImmutable::now()->diffInDays($report->validTo, false)) : null,
            'verified' => $report->verified,
        ];
    }

    /**
     * @return list<string>
     */
    private function invalidReasons(TlsReport $report, string $host): array
    {
        $now = CarbonImmutable::now();
        $reasons = [];

        if ($report->validTo !== null && $now->greaterThan($report->validTo)) {
            $reasons[] = 'sertifikat kedaluwarsa sejak '.$report->validTo->toDateString();
        }

        if ($report->validFrom !== null && $now->lessThan($report->validFrom)) {
            $reasons[] = 'sertifikat belum berlaku hingga '.$report->validFrom->toDateString();
        }

        if (! $report->matchesHost($host)) {
            $names = $report->subjectAltNames !== [] ? implode(', ', array_slice($report->subjectAltNames, 0, 5)) : (string) $report->subject;
            $reasons[] = "nama host {$host} tidak cocok dengan sertifikat ({$names})";
        }

        if ($report->selfSigned) {
            $reasons[] = 'sertifikat self-signed';
        }

        return $reasons;
    }

    private function checkExpiry(ScanContext $context, TlsReport $report, bool $valid, string $endpoint): void
    {
        $label = self::LABELS['tls-expiry'];

        if (! $valid || $report->validTo === null || $report->validFrom === null) {
            $context->observe('tls-expiry', $label, 'internal', ObservationStatus::NotApplicable, 'Sertifikat tidak valid, masa berlaku tidak dinilai terpisah.');

            return;
        }

        $now = CarbonImmutable::now();
        $remaining = $report->validTo->getTimestamp() - $now->getTimestamp();
        $total = max(1, $report->validTo->getTimestamp() - $report->validFrom->getTimestamp());
        $daysLeft = (int) floor($remaining / 86400);
        $raw = ['valid_from' => $report->validFrom->toIso8601String(), 'valid_to' => $report->validTo->toIso8601String(), 'days_left' => $daysLeft];

        // Aturan 1/4 mencegah sertifikat yang diperbarui otomatis dianggap temuan
        if ($daysLeft <= 30 && $remaining < $total / 4) {
            $detail = "sertifikat berakhir pada {$report->validTo->toDateString()} (sisa {$daysLeft} hari)";
            $context->observe('tls-expiry', $label, 'internal', ObservationStatus::Fail, ucfirst($detail).'.', $raw);
            $context->addFinding(new FindingData('tls-cert-expiring', 'internal', $detail, $endpoint, $raw));

            return;
        }

        $context->observe('tls-expiry', $label, 'internal', ObservationStatus::Pass, "Berlaku hingga {$report->validTo->toDateString()} (sisa {$daysLeft} hari).", $raw);
    }

    private function checkProtocols(ScanContext $context, string $host, string $ip, int $port, string $endpoint, TlsReport $report): void
    {
        $results = [];

        foreach (['TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'] as $version) {
            $result = $this->inspector->probeProtocol($host, $ip, $version, $port);

            // Kegagalan jaringan diulang satu kali sebelum dicatat ERROR (bagian 22.3)
            if ($result === 'error') {
                usleep(500_000);
                $result = $this->inspector->probeProtocol($host, $ip, $version, $port);
            }

            $results[$version] = $result;
        }

        $supported = array_keys(array_filter($results, fn ($r) => $r === 'accepted'));
        $context->overview['tls_protocols'] = $supported;
        $raw = ['probe' => $results, 'negotiated' => $report->protocol];

        $legacy = array_intersect_key($results, array_flip(['TLSv1.0', 'TLSv1.1']));
        $legacyAccepted = array_keys(array_filter($legacy, fn ($r) => $r === 'accepted'));
        $label = self::LABELS['tls-protocol'];

        if ($legacyAccepted !== []) {
            $detail = 'server menerima '.implode(' dan ', str_replace('TLSv', 'TLS ', $legacyAccepted));
            $context->observe('tls-protocol', $label, 'internal', ObservationStatus::Fail, ucfirst($detail).'.', $raw);
            $context->addFinding(new FindingData('tls-legacy-protocol', 'internal', $detail, $endpoint, $raw));

            return;
        }

        if (in_array('unsupported', $legacy, true)) {
            $context->observe('tls-protocol', $label, 'internal', ObservationStatus::NotAssessed, 'OpenSSL di mesin ini tidak mampu menguji TLS 1.0/1.1.', $raw);

            return;
        }

        if (in_array('error', $legacy, true)) {
            $context->observe('tls-protocol', $label, 'internal', ObservationStatus::Error, 'Pengujian TLS 1.0/1.1 gagal karena kesalahan jaringan.', $raw);

            return;
        }

        $context->observe('tls-protocol', $label, 'internal', ObservationStatus::Pass, 'TLS 1.0 dan TLS 1.1 ditolak. Didukung: '.(implode(', ', $supported) ?: '-').'.', $raw);
    }

    private function all(ScanContext $context, ObservationStatus $status, string $summary): void
    {
        foreach (self::LABELS as $key => $label) {
            $context->observe($key, $label, 'internal', $status, $summary);
        }
    }
}
