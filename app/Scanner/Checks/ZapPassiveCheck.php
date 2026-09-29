<?php

namespace App\Scanner\Checks;

use App\Enums\ObservationStatus;
use App\Scanner\Network\DnsResolver;
use App\Scanner\Parsers\ZapParser;
use App\Scanner\ScanContext;
use App\Scanner\Tools\ToolRunner;
use App\Scanner\Tools\ZapClient;
use RuntimeException;

/**
 * OWASP ZAP passive scan pada halaman utama (bagian 4, opsional, hanya Mode Standar). ZAP dijalankan
 * sebagai daemon; SIPRIKA hanya meminta satu halaman lewat API tanpa active scan atau spider.
 */
class ZapPassiveCheck extends ExternalToolCheck
{
    public function __construct(ToolRunner $tools, DnsResolver $dns, private ZapClient $zap)
    {
        parent::__construct($tools, $dns);
    }

    public function key(): string
    {
        return 'zap-passive';
    }

    public function label(): string
    {
        return 'OWASP ZAP Passive';
    }

    protected function tool(): string
    {
        return 'zap';
    }

    protected function envName(): string
    {
        return 'ZAP_URL';
    }

    public function isAvailable(): bool
    {
        return $this->zap->isConfigured();
    }

    protected function execute(ScanContext $context): void
    {
        $url = $context->reachableUrl();
        [$unassessable, $discarded] = $context->toolLimits($url);
        // Kunci katalog yang dinilai ZAP pada website ini, dipakai Coverage per kunci (bagian 22.10)
        $assessed = array_values(array_diff(array_unique(array_values(config('siprika_scanner.zap_map', []))), $unassessable));

        try {
            $alerts = $this->zap->passiveScan($url, $this->timeout($context));
        } catch (RuntimeException $e) {
            $this->observe($context, ObservationStatus::Error, mb_substr($e->getMessage(), 0, 400), ['url' => $url, 'assessed_keys' => $assessed]);

            return;
        }

        $parsed = ZapParser::parse($alerts);
        [$findings, $ignored] = $this->acceptedFindings($context, $parsed['findings'], $discarded);

        foreach ($findings as $finding) {
            $context->addFinding($finding);
        }

        $names = array_values(array_unique(array_column($parsed['alerts'], 'name')));
        $summary = ($names === [] ? 'Tidak ada alert passive scan.' : count($parsed['alerts']).' alert: '.implode(', ', array_slice($names, 0, 15)).'.')
            .self::ignoredSummary($ignored)
            .' Alert di luar katalog hanya informasi dan tidak masuk Risk Register.';

        $this->observe($context, match (true) {
            $findings !== [] => ObservationStatus::Fail,
            $names !== [] => ObservationStatus::Info,
            default => ObservationStatus::Pass,
        }, $summary, [
            'url' => $url,
            'assessed_keys' => $assessed,
            'ignored_keys' => $ignored,
            'alerts' => array_slice($parsed['alerts'], 0, 200),
        ]);
    }
}
