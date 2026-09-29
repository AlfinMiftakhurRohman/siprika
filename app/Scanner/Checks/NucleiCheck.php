<?php

namespace App\Scanner\Checks;

use App\Enums\ObservationStatus;
use App\Scanner\Data\FindingData;
use App\Scanner\Fingerprint;
use App\Scanner\Network\HttpFailure;
use App\Scanner\Parsers\NucleiParser;
use App\Scanner\ScanContext;
use App\Scanner\Tools\RunningTool;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Sleep;

/**
 * Nuclei safe scan dengan profil template yang disetujui per mode (bagian 26, config siprika.tools.nuclei.profiles).
 * Berjalan di latar belakang: karena dibatasi 15 request per detik, pemeriksaan berikutnya dikerjakan sambil menunggu.
 * Request yang gagal karena website kewalahan atau membatasi request diulang pada kecepatan lebih rendah
 * (config siprika.tools.nuclei.retry_*), supaya hasil tidak diam-diam tidak lengkap.
 */
class NucleiCheck extends ExternalToolCheck implements BackgroundCheck
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

    /**
     * Run yang sedang berjalan di latar belakang, null jika belum dimulai atau hasilnya sudah dibaca.
     *
     * rate: kecepatan run saat ini, retried: run ini sudah diulang, throttled: website pernah memblokir sehingga run
     * berikutnya tetap pada kecepatan rendah, stopped: website masih memblokir sehingga run berikutnya tidak dijalankan,
     * directory: folder kerja untuk -elog, notes: catatan pengulangan untuk ringkasan, attempts: jumlah request gagal
     * setiap run untuk raw observation.
     *
     * @var array{runs: list<array<string, list<string>>>, deadline: float, index: int, max_time: int, rate: int, retried: bool, throttled: bool, stopped: bool, directory: string, error_log: string, tool: RunningTool|null, output: string, problem: string|null, notes: list<string>, attempts: list<array<string, mixed>>}|null
     */
    private ?array $pending = null;

    protected function execute(ScanContext $context): void
    {
        $this->launch($context);
        $this->finish($context);
    }

    public function start(ScanContext $context): void
    {
        if ($this->preflight($context)) {
            $this->launch($context);
        }
    }

    public function isPending(): bool
    {
        return $this->pending !== null;
    }

    public function poll(): void
    {
        $this->pending['tool']?->poll();
    }

    public function finish(ScanContext $context): void
    {
        if ($this->pending === null) {
            return;
        }

        $directory = $this->pending['directory'];

        try {
            [$output, $problem] = $this->collect($context);
        } finally {
            File::deleteDirectory($directory);
        }

        $runs = $this->pending['runs'];
        $notes = $this->pending['notes'];
        $attempts = $this->pending['attempts'];
        $this->pending = null;

        [$unassessable, $discarded] = $context->toolLimits($context->reachableUrl());
        // Kunci katalog yang dinilai profil ini pada target ini, dipakai Coverage per kunci (bagian 22.10)
        $assessed = array_values(array_diff(config("siprika.tools.nuclei.profile_keys.{$context->mode->value}", []), $unassessable));

        if ($problem !== null && trim($output) === '') {
            $this->observe($context, ObservationStatus::Error, $problem.' Profil: '.self::describe($runs).'.', ['profile' => $runs, 'assessed_keys' => $assessed]);

            return;
        }

        $parsed = NucleiParser::parse($output);
        [$parsed['findings'], $ignored] = $this->acceptedFindings($context, $parsed['findings'], $discarded);

        foreach ($parsed['findings'] as $finding) {
            $context->addFinding($finding);
        }

        $context->addTechnologies($parsed['technologies']);
        $this->record($context, $runs, $parsed, $problem, $assessed, $ignored, $notes, $attempts);
    }

    /**
     * Mulai run pertama profil. Semua run berbagi satu batas waktu Nuclei per website.
     */
    private function launch(ScanContext $context): void
    {
        $this->pending = [
            'runs' => config("siprika.tools.nuclei.profiles.{$context->mode->value}", []),
            'deadline' => microtime(true) + $this->timeout($context),
            'index' => -1,
            'max_time' => 0,
            'rate' => (int) config('siprika.tools.nuclei.rate_limit'),
            'retried' => false,
            'throttled' => false,
            'stopped' => false,
            'directory' => $this->workDirectory(),
            'error_log' => '',
            'tool' => null,
            'output' => '',
            'problem' => null,
            'notes' => [],
            'attempts' => [],
        ];

        $this->startNextRun($context);
    }

    /**
     * Jalankan run berikutnya, atau ulangi run saat ini ($repeat), bila perlu hanya untuk template yang gagal ($retry).
     *
     * @param  array{templates?: string, template_ids?: list<string>}|null  $retry
     */
    private function startNextRun(ScanContext $context, bool $repeat = false, ?array $retry = null): void
    {
        $index = $this->pending['index'] + ($repeat ? 0 : 1);
        $this->pending['index'] = $index;
        $this->pending['tool'] = null;

        if (! $repeat) {
            $this->pending['retried'] = false;
            // Beberapa request gagal tidak memperlambat run berikutnya; website yang pernah memblokir tetap diperlambat
            $config = config('siprika.tools.nuclei');
            $this->pending['rate'] = $this->pending['throttled'] ? min((int) $config['rate_limit'], (int) $config['blocked_rate_limit']) : (int) $config['rate_limit'];
        }

        if (! isset($this->pending['runs'][$index])) {
            return;
        }

        $timeout = (int) floor($this->pending['deadline'] - microtime(true));

        if ($timeout <= 0) {
            $this->pending['problem'] = 'Nuclei tidak selesai karena melewati batas waktu, sebagian template belum dijalankan.';

            return;
        }

        // Nuclei berhenti sendiri sebelum proses dimatikan, supaya hasil yang sudah didapat tetap tertulis
        $this->pending['max_time'] = max(10, $timeout - 15);
        $this->pending['error_log'] = 'nuclei-errors-'.(count($this->pending['attempts']) + 1).'.jsonl';
        $run = $retry ?? $this->pending['runs'][$index];

        $this->pending['tool'] = $this->tools->start(
            'nuclei',
            self::arguments($context, $run, $this->pending['max_time'], $this->pending['rate'], $this->pending['error_log']),
            $timeout,
            $this->pending['directory'],
        );
    }

    /**
     * Tunggu run yang berjalan, lalu jalankan sisa run profil secara berurutan.
     *
     * @return array{0: string, 1: string|null} output JSONL gabungan dan alasan jika terpotong atau gagal
     */
    private function collect(ScanContext $context): array
    {
        while ($this->pending['tool'] !== null) {
            $result = $this->pending['tool']->wait();
            $maxTime = $this->pending['max_time'];
            $this->pending['output'] = self::mergeOutput($this->pending['output'], $result->output);

            if ($result->timedOut || $result->seconds >= $maxTime - 1) {
                $this->pending['problem'] = "Nuclei dihentikan karena melewati batas waktu ({$maxTime} detik), sebagian template belum dijalankan.";

                break;
            }

            if (! $result->successful && trim($result->output) === '') {
                $this->pending['problem'] = $result->errorSummary();

                break;
            }

            if ($this->retryOverloadedRun($context)) {
                continue;
            }

            if ($this->pending['stopped']) {
                break;
            }

            $this->startNextRun($context);
        }

        return [$this->pending['output'], $this->pending['problem']];
    }

    /**
     * Periksa run yang baru selesai. Request yang gagal diulang pada kecepatan lebih rendah: hanya template yang gagal,
     * atau seluruh run jika website memblokir (atau -elog tidak menyebut template). Mengembalikan true jika run diulang.
     */
    private function retryOverloadedRun(ScanContext $context): bool
    {
        $config = config('siprika.tools.nuclei');
        [$errors, $otherFailures] = self::failedRequests($this->pending['directory'].DIRECTORY_SEPARATOR.$this->pending['error_log'], $context->reachableUrl());
        $blocked = $this->blockedAfterRun($context);
        $rate = $this->pending['rate'];
        $failed = count($errors);

        $this->pending['attempts'][] = array_filter([
            'run' => $this->pending['index'] + 1,
            'retry' => $this->pending['retried'],
            'rate_limit' => $rate,
            'failed_requests' => $failed,
            'other_failures' => $otherFailures ?: null,
            'blocked' => $blocked,
        ], fn ($value) => $value !== null);

        if ($failed === 0 && $blocked === null) {
            return false;
        }

        $reason = $blocked ?? "{$failed} request ke website gagal (timeout atau koneksi ditolak/diputus)";
        // Uji e-sakip 15 request/detik: 62 request gagal tetapi hasil lengkap, jadi hanya pemblokiran yang mengulang seluruh run
        $wholeRun = $blocked !== null;
        // Timeout acak diulang sedikit lebih lambat; website yang memblokir diulang jauh lebih lambat
        $retryRate = min($rate, (int) $config[$wholeRun ? 'blocked_rate_limit' : 'retry_rate_limit']);

        // Sudah diulang: sisa kegagalan kecil hanya dicatat, kegagalan besar membuat hasil Nuclei tidak lengkap (ERROR)
        if ($this->pending['retried']) {
            if ($wholeRun || $failed >= $config['max_failed_requests']) {
                $this->pending['problem'] = "Website membatasi atau kewalahan menerima request Nuclei ({$reason} pada {$rate} request per detik, setelah diulang), sehingga hasil Nuclei mungkin tidak lengkap.";
            } else {
                $this->pending['notes'][] = "{$failed} request tetap gagal setelah diulang.";
            }

            return false;
        }

        $retry = $wholeRun ? null : $this->retryTemplates($errors);

        if ($retry === null) {
            $this->pending['throttled'] = true;
            Sleep::for((int) $config['retry_cooldown'])->seconds();

            // Website yang masih memblokir setelah jeda tidak diulang, supaya tidak dibebani ribuan request lagi
            $stillBlocked = $blocked !== null ? $this->blockedAfterRun($context) : null;

            if ($stillBlocked !== null) {
                $this->pending['problem'] = "Website memblokir request Nuclei ({$blocked} pada {$rate} request per detik) dan masih memblokir setelah jeda {$config['retry_cooldown']} detik, sehingga Nuclei tidak dilanjutkan dan hasilnya mungkin tidak lengkap.";
                $this->pending['stopped'] = true;

                return false;
            }
        }

        $this->pending['notes'][] = ($retry === null ? 'Run diulang' : 'Template yang gagal diulang')." pada {$retryRate} request per detik karena {$reason} pada {$rate} request per detik.";
        $this->pending['rate'] = $retryRate;
        $this->pending['retried'] = true;
        $this->startNextRun($context, repeat: true, retry: $retry);

        return $this->pending['tool'] !== null;
    }

    /**
     * Halaman utama dibuka lagi setelah Nuclei berjalan: 429, 5xx, atau halaman blokir WAF berarti website mulai
     * membatasi SIPRIKA. Dilewati jika halaman utama sudah diblokir sejak awal (ditangani waf_limited_keys).
     */
    private function blockedAfterRun(ScanContext $context): ?string
    {
        if ($context->homepage === null || $context->wafBlocked) {
            return null;
        }

        try {
            $response = $context->http->get($context->reachableUrl(), false, 256 * 1024);
        } catch (HttpFailure) {
            return 'halaman utama tidak dapat diakses setelah Nuclei berjalan';
        }

        return match (true) {
            $response->status === 429 => 'website membalas 429 Too Many Requests',
            $response->status >= 500 && $context->homepage->status < 500 => "halaman utama membalas status {$response->status}",
            Fingerprint::isWafBlockPage($response) => 'WAF/CDN menampilkan halaman blokir',
            default => null,
        };
    }

    /**
     * Request gagal dari -elog Nuclei (satu baris JSON per request: template, type, input, error). Hanya request HTTP
     * ke website itu sendiri (skema, host, dan port sama dengan URL yang diperiksa) yang menandakan website kewalahan.
     * Kegagalan lain memang wajar: template tcp/ssl/dns/javascript dan port lain yang tertutup tidak dijawab website
     * (uji e-sakip: 61 dari 62 request gagal termasuk jenis ini, baik pada 5, 10, maupun 15 request per detik).
     *
     * @return array{0: list<array<string, mixed>>, 1: int} request ke website yang gagal, jumlah kegagalan lain
     */
    private static function failedRequests(string $path, string $url): array
    {
        if (! is_file($path)) {
            return [[], 0];
        }

        $errors = array_values(array_filter(array_map(
            fn (string $line) => json_decode($line, true),
            preg_split('/\R/', (string) file_get_contents($path)),
        ), 'is_array'));

        $website = array_values(array_filter($errors, fn (array $error) => ($error['type'] ?? null) === 'http'
            && self::origin((string) ($error['input'] ?? '')) === self::origin($url)));

        return [$website, count($errors) - count($website)];
    }

    /**
     * Skema, host, dan port URL, contoh "https://web.jemberkab.go.id:443".
     */
    private static function origin(string $url): ?string
    {
        $parts = parse_url($url);

        if (! isset($parts['scheme'], $parts['host'])) {
            return null;
        }

        $scheme = strtolower($parts['scheme']);

        return $scheme.'://'.strtolower($parts['host']).':'.($parts['port'] ?? ($scheme === 'https' ? 443 : 80));
    }

    /**
     * Template yang gagal untuk diulang. -elog menulis path file template (diulang dengan -t lewat file daftar, supaya
     * perintah tidak terlalu panjang) atau hanya ID-nya (diulang dengan -id). Null jika tidak ada nama template,
     * sehingga seluruh run yang diulang.
     *
     * @param  list<array<string, mixed>>  $errors
     * @return array{templates?: string, template_ids?: list<string>}|null
     */
    private function retryTemplates(array $errors): ?array
    {
        $names = array_values(array_unique(array_filter(array_map(fn (array $error) => trim((string) ($error['template'] ?? '')), $errors))));
        $paths = array_values(array_filter($names, fn (string $name) => str_contains($name, '/') || str_contains($name, '\\') || str_ends_with($name, '.yaml')));
        $ids = array_values(array_diff($names, $paths));

        if ($names === []) {
            return null;
        }

        $retry = [];

        if ($paths !== []) {
            $retry['templates'] = 'nuclei-retry-'.count($this->pending['attempts']).'.txt';
            file_put_contents($this->pending['directory'].DIRECTORY_SEPARATOR.$retry['templates'], implode("\n", $paths)."\n");
        }

        if ($ids !== []) {
            $retry['template_ids'] = $ids;
        }

        return $retry;
    }

    /**
     * Gabungkan output JSONL run yang diulang tanpa hasil ganda (template, matcher, lokasi, dan nilai yang diambil sama).
     */
    private static function mergeOutput(string $existing, string $new): string
    {
        $lines = [];

        foreach (preg_split('/\R/', $existing."\n".$new) as $line) {
            $item = json_decode(trim($line), true);

            if (! is_array($item)) {
                continue;
            }

            $key = json_encode([$item['template-id'] ?? null, $item['matcher-name'] ?? null, $item['matched-at'] ?? null, $item['extracted-results'] ?? null]);
            $lines[$key] ??= trim($line);
        }

        return implode("\n", $lines);
    }

    /**
     * Pemeriksaan yang terpotong atau gagal dicatat ERROR (bagian 26), temuan yang sempat didapat tetap disimpan.
     *
     * @param  list<array<string, list<string>>>  $runs
     * @param  array{findings: list<FindingData>, technologies: list<array<string, mixed>>, results: list<array<string, mixed>>}  $parsed
     * @param  list<string>  $assessed  kunci katalog yang dinilai
     * @param  array<string, string>  $ignored  kunci yang hasilnya diabaikan => alasan
     * @param  list<string>  $notes  catatan pengulangan run
     * @param  list<array<string, mixed>>  $attempts  jumlah request gagal setiap run
     */
    private function record(ScanContext $context, array $runs, array $parsed, ?string $problem, array $assessed, array $ignored, array $notes = [], array $attempts = []): void
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
            .self::ignoredSummary($ignored)
            .($notes !== [] ? ' '.implode(' ', $notes) : '')
            .' Profil: '.self::describe($runs).'.';

        $this->observe($context, $status, $summary, [
            'url' => $context->reachableUrl(),
            'profile' => $runs,
            'incomplete' => $problem !== null,
            'rate_limit' => (int) config('siprika.tools.nuclei.rate_limit'),
            'attempts' => $attempts,
            'assessed_keys' => $assessed,
            'ignored_keys' => $ignored,
            'results' => array_slice($parsed['results'], 0, 200),
        ]);
    }

    /**
     * @param  array{ids?: list<string>, tags?: list<string>, severity?: list<string>, templates?: string, template_ids?: list<string>}  $run
     * @return list<string>
     */
    private static function arguments(ScanContext $context, array $run, int $maxTime, int $rate, string $errorLog): array
    {
        $config = config('siprika.tools.nuclei');

        // URL yang benar-benar dapat diakses (redirect sudah diikuti SafeHttpClient), contoh http:// jika website tidak melayani HTTPS.
        // -dr: redirect tidak diikuti Nuclei supaya tidak keluar dari domain yang sudah divalidasi (SSRF).
        // -no-stdin: tanpa ini Nuclei menunggu daftar target dari stdin jika stdin bukan terminal dan tidak pernah selesai.
        $arguments = [
            '-u', $context->reachableUrl(),
            '-jsonl', '-silent', '-nc', '-duc', '-ni', '-or', '-no-stdin', '-dr',
            '-rl', (string) $rate,
            '-c', (string) $rate,
            '-timeout', '10',
            '-retries', '1',
            '-mt', "{$maxTime}s",
            // Request yang gagal dicatat di folder kerja (path relatif, juga berlaku untuk Nuclei di WSL)
            '-elog', $errorLog,
            '-mhe', (string) $config['max_host_errors'],
        ];

        // Pengulangan template yang gagal memakai daftar template dari -elog; tag terlarang tetap dikecualikan
        $filters = isset($run['templates']) || isset($run['template_ids'])
            ? [
                ...(isset($run['templates']) ? ['-t', $run['templates']] : []),
                ...(isset($run['template_ids']) ? ['-id', implode(',', $run['template_ids'])] : []),
                '-etags', implode(',', config('siprika.tools.nuclei.exclude_tags')),
            ]
            : self::filterArguments($run);

        return [...$arguments, ...$filters, '-H', 'User-Agent: '.config('siprika.scan.user_agent')];
    }

    /**
     * Filter template satu run profil (id, tag, severity, tag yang dikecualikan). Dipakai juga siprika:check-nuclei.
     *
     * @param  array{ids?: list<string>, tags?: list<string>, severity?: list<string>}  $run
     * @return list<string>
     */
    public static function filterArguments(array $run): array
    {
        $arguments = [];

        foreach (['ids' => '-id', 'tags' => '-tags', 'severity' => '-s'] as $key => $flag) {
            if (! empty($run[$key])) {
                array_push($arguments, $flag, implode(',', $run[$key]));
            }
        }

        return [...$arguments, '-etags', implode(',', config('siprika.tools.nuclei.exclude_tags'))];
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
