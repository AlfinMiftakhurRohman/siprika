<?php

namespace App\Scanner\Checks;

use App\Enums\ObservationStatus;
use App\Scanner\Parsers\TestsslParser;
use App\Scanner\ScanContext;
use App\Scanner\Tools\ToolResult;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Sleep;

/**
 * TLS lengkap dengan testssl.sh: protokol, rantai sertifikat, dan cipher lemah.
 */
class TestsslCheck extends ExternalToolCheck
{
    /**
     * Jeda sebelum testssl.sh diulang karena koneksi ke website gagal (detik).
     */
    private const RETRY_DELAY = 5;

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

        $this->inWorkDirectory(function (string $directory) use ($context) {
            [$result, $parsed] = $this->runTestssl($context, $directory);
            $raw = [];

            // Koneksi yang gagal sejak awal (contoh Wi-Fi tersendat) diulang satu kali setelah jeda singkat (bagian 22.3)
            if (self::isConnectionProblem($parsed['problem'] ?? null)) {
                $raw['retried'] = $parsed['problem'];
                Sleep::for(self::RETRY_DELAY)->seconds();
                [$result, $parsed] = $this->runTestssl($context, $directory);
            }

            if ($parsed === null) {
                $this->result($context, ObservationStatus::Error, $result->errorSummary(), $raw);

                return;
            }

            $raw['items'] = array_slice($parsed['relevant'], 0, 100);

            // testssl.sh yang gagal di tengah jalan tidak boleh dianggap PASS (bagian 22.2)
            if ($parsed['problem'] !== null) {
                $lost = self::isConnectionProblem($parsed['problem']) && $this->connectionLost($context) ? ' Koneksi internet laptop terputus saat itu.' : '';
                $this->result($context, ObservationStatus::Error, 'testssl.sh tidak dapat menyelesaikan pemeriksaan: '.mb_substr($parsed['problem'], 0, 300).$lost, $raw);

                return;
            }

            foreach ($parsed['findings'] as $finding) {
                $context->addFinding($finding);
            }

            $this->result(
                $context,
                $parsed['findings'] === [] ? ObservationStatus::Pass : ObservationStatus::Fail,
                $parsed['summary'],
                $raw,
            );
        });
    }

    /**
     * Jalankan testssl.sh satu kali.
     *
     * @return array{0: ToolResult, 1: array<string, mixed>|null} hasil proses, dan hasil TestsslParser (null jika testssl.json tidak terbaca)
     */
    private function runTestssl(ScanContext $context, string $directory): array
    {
        $file = $directory.DIRECTORY_SEPARATOR.'testssl.json';
        // testssl.sh menolak menulis ke file JSON yang sudah ada dari percobaan sebelumnya
        File::delete($file);

        // Nama file relatif supaya tetap benar saat testssl.sh dijalankan lewat WSL
        $result = $this->tools->run('testssl', [
            '--jsonfile', 'testssl.json', '--quiet', '--color', '0', '--warnings', 'off',
            '--ip', (string) $context->primaryIp(), '-p', '-S', '-s', "{$context->host()}:{$context->httpsPort()}",
        ], $this->timeout($context), $directory);

        $items = is_file($file) ? json_decode((string) file_get_contents($file), true) : null;

        return [$result, is_array($items) ? TestsslParser::parse($items, $context->httpsEndpoint()) : null];
    }

    /**
     * testssl.sh berhenti karena tidak dapat membuka koneksi TCP ke website, contoh "Can't connect to ..."
     * atau "repeated TCP connect problems".
     */
    private static function isConnectionProblem(?string $problem): bool
    {
        return $problem !== null && preg_match("/can't connect|couldn't connect|tcp connect problem|unable to open a socket/i", $problem) === 1;
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
