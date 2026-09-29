<?php

namespace App\Console\Commands;

use App\Scanner\ScanRecovery;
use App\Scanner\Tools\ToolRunner;
use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;
use Illuminate\Foundation\Console\ServeCommand;
use ReflectionClass;
use Symfony\Component\Process\PhpExecutableFinder;
use Symfony\Component\Process\Process;

#[Signature('siprika:serve {--host=127.0.0.1} {--port=8000}')]
#[Description('Menjalankan web server, queue worker, llama-server (AI_SERVER_COMMAND), dan ZAP (ZAP_SERVER_COMMAND) dalam satu perintah')]
class SiprikaServe extends Command
{
    /**
     * Layanan opsional: jika berhenti, pemeriksaan tetap berjalan tanpa layanan itu.
     */
    private const OPTIONAL = [
        'ai' => 'llama-server berhenti (exit code %s%s). Analisis AI memakai teks katalog. Periksa AI_SERVER_COMMAND.',
        'zap' => 'ZAP berhenti (exit code %s%s). Pemeriksaan OWASP ZAP Passive dicatat ERROR. Periksa ZAP_SERVER_COMMAND.',
    ];

    /**
     * Log layanan opsional sangat banyak, hanya status penting yang ditampilkan.
     */
    private const LOG_FILTERS = [
        'ai' => '/error|listening|model loaded|failed/i',
        'zap' => '/is now listening|BindException|address already in use|Cannot start|DaemonBootstrap/i',
    ];

    public function handle(ScanRecovery $recovery): int
    {
        $host = (string) $this->option('host');
        $port = (int) $this->option('port');

        // SIPRIKA tanpa login: semua yang dapat membuka alamatnya dapat melihat hasil dan memulai pemeriksaan
        if (! in_array($host, ['127.0.0.1', 'localhost', '::1'], true)) {
            $this->components->warn("--host={$host} membuka SIPRIKA ke jaringan. SIPRIKA tanpa login, sehingga siapa pun di jaringan itu dapat melihat hasil pemeriksaan dan memulai pemeriksaan.");
        }

        // Berhenti sebelum menjalankan apa pun, supaya tidak ada queue worker kedua atau llama-server ganda.
        // Alamat 0.0.0.0 (semua antarmuka) tidak dapat dihubungi langsung, jadi dicek lewat 127.0.0.1.
        if (self::portInUse(in_array($host, ['0.0.0.0', '::'], true) ? '127.0.0.1' : $host, $port)) {
            $this->components->error("Port {$port} sudah dipakai. Jika SIPRIKA sudah berjalan, buka http://{$host}:{$port}. Jika dipakai aplikasi lain, jalankan dengan --port=".($port + 1).'.');

            return self::FAILURE;
        }

        $this->recoverStoppedScans($recovery);

        $php = (new PhpExecutableFinder)->find(false) ?: PHP_BINARY;
        $artisan = base_path('artisan');

        $processes = [
            // Server bawaan PHP seperti artisan serve, ditambah OPcache supaya halaman jauh lebih cepat
            'server' => new Process([$php, ...self::opcacheArguments(), '-S', "{$host}:{$port}", self::routerScript()], public_path(), null, null, null),
            // Satu worker supaya website diperiksa satu per satu sesuai urutan antrean
            'queue' => new Process([$php, $artisan, 'queue:listen', '--tries=1', '--timeout=0'], base_path(), null, null, null),
        ];

        $optional = [
            'ai' => $this->optionalServer('llama-server', config('siprika.ai.enabled') ? config('siprika.ai.server_command') : null, (string) config('siprika.ai.url')),
            'zap' => $this->optionalServer('ZAP', config('siprika.tools.zap.server_command'), (string) config('siprika.tools.zap.url')),
        ];

        $processes += array_filter($optional);

        foreach ($processes as $process) {
            $process->start();
        }

        $this->components->info("SIPRIKA berjalan di http://{$host}:{$port}  (Ctrl+C untuk berhenti)");

        while (true) {
            foreach ($processes as $name => $process) {
                $this->printOutput($name, $process->getIncrementalOutput().$process->getIncrementalErrorOutput());

                if ($process->isRunning()) {
                    continue;
                }

                // AI dan ZAP opsional: jika berhenti, scan tetap berjalan (bagian 9 dan bagian 4)
                if (isset(self::OPTIONAL[$name])) {
                    $reason = trim((string) collect(preg_split('/\R/', trim($process->getErrorOutput())))->last());
                    $this->components->warn(sprintf(self::OPTIONAL[$name], $process->getExitCode(), $reason !== '' ? ": {$reason}" : ''));
                    unset($processes[$name]);

                    continue;
                }

                $this->components->error("Proses {$name} berhenti (exit code {$process->getExitCode()}).");

                foreach ($processes as $other) {
                    $other->stop(3);
                }

                return self::FAILURE;
            }

            usleep(300_000);
        }
    }

    /**
     * Pemeriksaan yang terhenti karena SIPRIKA sebelumnya dihentikan di tengah jalan ditandai gagal, dan kunci
     * antreannya dilepas. Hanya dijalankan jika port web belum dipakai (tidak ada SIPRIKA lain yang memeriksa).
     */
    private function recoverStoppedScans(ScanRecovery $recovery): void
    {
        $stopped = $recovery->recover();

        if ($stopped > 0) {
            $this->components->warn("{$stopped} pemeriksaan terhenti saat SIPRIKA dihentikan sebelumnya dan ditandai gagal. Gunakan Pindai Ulang untuk memeriksa lagi.");
        }
    }

    /**
     * Layanan opsional (llama-server, ZAP) dijalankan hanya jika perintahnya diisi dan port-nya belum dipakai.
     */
    private function optionalServer(string $label, ?string $command, string $url): ?Process
    {
        $command = trim((string) $command);

        // Tanpa URL layanan tidak dipakai pemeriksaan, jadi tidak perlu dijalankan
        if ($command === '' || trim($url) === '') {
            return null;
        }

        $parts = parse_url($url);

        if (self::portInUse($parts['host'] ?? '127.0.0.1', (int) ($parts['port'] ?? 80))) {
            $this->components->info("{$label} sudah berjalan di {$url}, tidak dijalankan ulang.");

            return null;
        }

        $this->components->info("Menjalankan {$label}.");

        return new Process(self::serverArguments($command), base_path(), null, null, null);
    }

    /**
     * Argumen perintah layanan. Program dengan path relatif (contoh storage/app/llama.cpp/llama-server.exe)
     * dihitung dari folder SIPRIKA, supaya tetap jalan saat folder dipindah ke laptop atau drive lain.
     * Argumen relatif lain (contoh -m storage/app/models/...) memakai folder kerja SIPRIKA.
     *
     * @return list<string>
     */
    public static function serverArguments(string $command): array
    {
        $arguments = ToolRunner::splitCommand($command);
        $isAbsolute = preg_match('~^([a-z]:)?[\\/]~i', $arguments[0] ?? '') === 1;

        if ($arguments !== [] && ! $isAbsolute && is_file(base_path($arguments[0]))) {
            $arguments[0] = base_path($arguments[0]);
        }

        return $arguments;
    }

    /**
     * Argumen PHP untuk mengaktifkan OPcache pada web server: kode tidak dikompilasi ulang setiap halaman dibuka.
     * Perubahan file tetap terbaca karena OPcache tetap memeriksa waktu ubah file. Kosong jika OPcache tidak tersedia.
     *
     * @return list<string>
     */
    public static function opcacheArguments(): array
    {
        if (extension_loaded('Zend OPcache')) {
            return ['-d', 'opcache.enable_cli=1'];
        }

        $file = PHP_OS_FAMILY === 'Windows' ? 'php_opcache.dll' : 'opcache.so';

        return is_file(ini_get('extension_dir').DIRECTORY_SEPARATOR.$file)
            ? ['-d', 'zend_extension=opcache', '-d', 'opcache.enable_cli=1']
            : [];
    }

    /**
     * Router server bawaan PHP yang juga dipakai artisan serve (meniru mod_rewrite ke public/index.php).
     */
    public static function routerScript(): string
    {
        return is_file(base_path('server.php'))
            ? base_path('server.php')
            : dirname((string) (new ReflectionClass(ServeCommand::class))->getFileName(), 2).'/resources/server.php';
    }

    /**
     * Baris log web server yang ditampilkan, contoh "09:20:14 GET /targets/27". Halaman Laravel hanya dicatat router
     * (server.php, jamnya UTC), sehingga jam diambil saat baris dibaca. Baris koneksi, polling progress (setiap
     * 2 detik), dan file CSS/JS yang berhasil dikirim disembunyikan supaya pesan penting tidak tenggelam.
     */
    public static function serverLogLine(string $line): ?string
    {
        // Halaman Laravel: "[Mon Sep 28 02:20:14 2026] 127.0.0.1:53422 [GET] URI: /targets/27"
        if (preg_match('/^\[[^\]]+\] \S+ \[(\w+)\] URI: (\S+)$/', $line, $match)) {
            return preg_match('#^/scans/\d+/progress$#', $match[2]) ? null : now()->format('H:i:s')." {$match[1]} {$match[2]}";
        }

        // File di folder public dikirim langsung oleh PHP: "[...] 127.0.0.1:53422 [404]: GET /favicon.ico"
        if (preg_match('/^\[[^\]]+\] \S+ \[(\d{3})\]: (\w+) (\S+)/', $line, $match)) {
            return (int) $match[1] >= 400 ? now()->format('H:i:s')." {$match[2]} {$match[3]} [{$match[1]}]" : null;
        }

        return preg_match('/ (Accepted|Closing)$| Closed without sending a request/', $line) ? null : $line;
    }

    private static function portInUse(string $host, int $port): bool
    {
        $socket = @fsockopen($host, $port, $errno, $errstr, 1);

        if ($socket === false) {
            return false;
        }

        fclose($socket);

        return true;
    }

    private function printOutput(string $name, string $output): void
    {
        foreach (preg_split('/\R/', trim($output)) as $line) {
            $line = $name === 'server' ? self::serverLogLine($line) : $line;

            if ($line === null || $line === '' || (isset(self::LOG_FILTERS[$name]) && ! preg_match(self::LOG_FILTERS[$name], $line))) {
                continue;
            }

            $this->line("<fg=gray>[{$name}]</> {$line}");
        }
    }
}
