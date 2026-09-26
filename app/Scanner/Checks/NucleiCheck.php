<?php

namespace App\Scanner\Checks;

use App\Enums\ObservationStatus;
use App\Scanner\Data\FindingData;
use App\Scanner\Parsers\NucleiParser;
use App\Scanner\ScanContext;

/**
 * Nuclei safe scan dengan profil template yang disetujui per mode (bagian 26, config siprika.tools.nuclei.profiles).
 */
class NucleiCheck extends ExternalToolCheck
{
    public function key(): string
    {
        return 'nuclei';
    }

    public function label(): string
    {
        return 'Nuclei';
    }

    protected function tool(): string
    {
        return 'nuclei';
    }

    protected function envName(): string
    {
        return 'NUCLEI_PATH';
    }

    protected function execute(ScanContext $context): void
    {
        $runs = config("siprika.tools.nuclei.profiles.{$context->mode->value}", []);
        [$output, $problem] = $this->runProfile($context, $runs);

        if ($problem !== null && trim($output) === '') {
            $this->observe($context, ObservationStatus::Error, $problem.' Profil: '.self::describe($runs).'.', ['profile' => $runs]);

            return;
        }

        $parsed = NucleiParser::parse($output);

        foreach ($parsed['findings'] as $finding) {
            $context->addFinding($finding);
        }

        $context->addTechnologies($parsed['technologies']);
        $this->record($context, $runs, $parsed, $problem);
    }

    /**
     * Jalankan setiap run profil secara berurutan. Semua run berbagi satu batas waktu Nuclei per website.
     *
     * @param  list<array<string, list<string>>>  $runs
     * @return array{0: string, 1: string|null} output JSONL gabungan dan alasan jika terpotong atau gagal
     */
    private function runProfile(ScanContext $context, array $runs): array
    {
        $deadline = microtime(true) + $this->timeout($context);
        $output = '';

        foreach ($runs as $run) {
            $timeout = (int) floor($deadline - microtime(true));

            if ($timeout <= 0) {
                return [$output, 'Nuclei tidak selesai karena melewati batas waktu, sebagian template belum dijalankan.'];
            }

            // Nuclei berhenti sendiri sebelum proses dimatikan, supaya hasil yang sudah didapat tetap tertulis
            $maxTime = max(10, $timeout - 15);
            $started = microtime(true);
            $result = $this->tools->run('nuclei', self::arguments($context, $run, $maxTime), $timeout);
            $output .= $result->output."\n";

            if ($result->timedOut || microtime(true) - $started >= $maxTime - 1) {
                return [$output, "Nuclei dihentikan karena melewati batas waktu ({$maxTime} detik), sebagian template belum dijalankan."];
            }

            if (! $result->successful && trim($result->output) === '') {
                return [$output, $result->errorSummary()];
            }
        }

        return [$output, null];
    }

    /**
     * Pemeriksaan yang terpotong atau gagal dicatat ERROR (bagian 26), temuan yang sempat didapat tetap disimpan.
     *
     * @param  list<array<string, list<string>>>  $runs
     * @param  array{findings: list<FindingData>, technologies: list<array<string, mixed>>, results: list<array<string, mixed>>}  $parsed
     */
    private function record(ScanContext $context, array $runs, array $parsed, ?string $problem): void
    {
        $status = match (true) {
            $problem !== null => ObservationStatus::Error,
            array_filter($parsed['findings'], fn (FindingData $f) => ! NucleiParser::isInformational($f)) !== [] => ObservationStatus::Fail,
            $parsed['findings'] !== [] => ObservationStatus::Info,
            default => ObservationStatus::Pass,
        };

        $count = count($parsed['results']);
        $templates = array_slice(array_unique(array_column($parsed['results'], 'template')), 0, 15);
        $summary = ($problem !== null ? $problem.' ' : '')
            .($count === 0 ? 'Tidak ada template yang cocok.' : "{$count} hasil: ".implode(', ', $templates).'.')
            .' Profil: '.self::describe($runs).'.';

        $this->observe($context, $status, $summary, [
            'url' => $context->reachableUrl(),
            'profile' => $runs,
            'incomplete' => $problem !== null,
            'results' => array_slice($parsed['results'], 0, 200),
        ]);
    }

    /**
     * @param  array{ids?: list<string>, tags?: list<string>, severity?: list<string>}  $run
     * @return list<string>
     */
    private static function arguments(ScanContext $context, array $run, int $maxTime): array
    {
        $config = config('siprika.tools.nuclei');

        // URL yang benar-benar dapat diakses (redirect sudah diikuti SafeHttpClient), contoh http:// jika website tidak melayani HTTPS.
        // -dr: redirect tidak diikuti Nuclei supaya tidak keluar dari domain yang sudah divalidasi (SSRF).
        // -no-stdin: tanpa ini Nuclei menunggu daftar target dari stdin jika stdin bukan terminal dan tidak pernah selesai.
        $arguments = [
            '-u', $context->reachableUrl(),
            '-jsonl', '-silent', '-nc', '-duc', '-ni', '-or', '-no-stdin', '-dr',
            '-rl', (string) $config['rate_limit'],
            '-c', '5',
            '-timeout', '10',
            '-retries', '1',
            '-mt', "{$maxTime}s",
        ];

        foreach (['ids' => '-id', 'tags' => '-tags', 'severity' => '-s'] as $key => $flag) {
            if (! empty($run[$key])) {
                array_push($arguments, $flag, implode(',', $run[$key]));
            }
        }

        return [...$arguments,
            '-etags', implode(',', $config['exclude_tags']),
            '-H', 'User-Agent: '.config('siprika.scan.user_agent'),
        ];
    }

    /**
     * Ringkasan profil untuk Coverage, contoh: "10 template informasi (...); tag exposure, ssl (severity high, critical)".
     *
     * @param  list<array{ids?: list<string>, tags?: list<string>, severity?: list<string>}>  $runs
     */
    public static function describe(array $runs): string
    {
        return implode('; ', array_map(function (array $run) {
            $parts = [];

            if (! empty($run['ids'])) {
                $parts[] = count($run['ids']).' template informasi ('.implode(', ', $run['ids']).')';
            }

            if (! empty($run['tags'])) {
                $parts[] = 'tag '.implode(', ', $run['tags']);
            }

            if (! empty($run['severity'])) {
                $parts[] = '(severity '.implode(', ', $run['severity']).')';
            }

            return implode(' ', $parts);
        }, $runs));
    }
}
