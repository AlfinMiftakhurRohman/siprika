<?php

namespace App\Scanner\Checks;

use App\Enums\ObservationStatus;
use App\Scanner\Parsers\TestsslParser;
use App\Scanner\ScanContext;

/**
 * TLS lengkap dengan testssl.sh: protokol, rantai sertifikat, dan cipher lemah.
 */
class TestsslCheck extends ExternalToolCheck
{
    public function key(): string
    {
        return 'testssl';
    }

    public function label(): string
    {
        return 'testssl.sh';
    }

    protected function tool(): string
    {
        return 'testssl';
    }

    protected function envName(): string
    {
        return 'TESTSSL_PATH';
    }

    protected function execute(ScanContext $context): void
    {
        if (! $context->httpsAvailable) {
            $context->httpsRefused()
                ? $this->result($context, ObservationStatus::NotApplicable, 'HTTPS tidak tersedia pada website ini.')
                : $this->result($context, ObservationStatus::Error, 'HTTPS tidak dapat diakses: '.$context->httpsFailureLabel().'.');

            return;
        }

        $host = $context->host();
        $ip = (string) $context->primaryIp();

        $this->inWorkDirectory(function (string $directory) use ($context, $host, $ip) {
            // Nama file relatif supaya tetap benar saat testssl.sh dijalankan lewat WSL
            $result = $this->tools->run('testssl', [
                '--jsonfile', 'testssl.json', '--quiet', '--color', '0', '--warnings', 'off',
                '--ip', $ip, '-p', '-S', '-s', "{$host}:{$context->httpsPort()}",
            ], $this->timeout($context), $directory);

            $file = $directory.DIRECTORY_SEPARATOR.'testssl.json';
            $items = is_file($file) ? json_decode((string) file_get_contents($file), true) : null;

            if (! is_array($items)) {
                $this->result($context, ObservationStatus::Error, $result->errorSummary());

                return;
            }

            $parsed = TestsslParser::parse($items, $context->httpsEndpoint());

            // testssl.sh yang gagal di tengah jalan tidak boleh dianggap PASS (bagian 22.2)
            if ($parsed['problem'] !== null) {
                $this->result($context, ObservationStatus::Error, 'testssl.sh tidak dapat menyelesaikan pemeriksaan: '.mb_substr($parsed['problem'], 0, 300), ['items' => array_slice($parsed['relevant'], 0, 100)]);

                return;
            }

            foreach ($parsed['findings'] as $finding) {
                $context->addFinding($finding);
            }

            $this->result(
                $context,
                $parsed['findings'] === [] ? ObservationStatus::Pass : ObservationStatus::Fail,
                $parsed['summary'],
                ['items' => array_slice($parsed['relevant'], 0, 100)],
            );
        });
    }

    /**
     * Observation testssl.sh beserta kunci katalog yang dinilainya, untuk Coverage per kunci (bagian 22.10).
     *
     * @param  array<string, mixed>  $raw
     */
    private function result(ScanContext $context, ObservationStatus $status, string $summary, array $raw = []): void
    {
        $this->observe($context, $status, $summary, $raw + ['assessed_keys' => TestsslParser::KEYS]);
    }
}
