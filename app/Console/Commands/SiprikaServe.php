<?php

namespace App\Console\Commands;

use App\Scanner\Tools\ToolRunner;
use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;
use Symfony\Component\Process\PhpExecutableFinder;
use Symfony\Component\Process\Process;

#[Signature('siprika:serve {--host=127.0.0.1} {--port=8000}')]
#[Description('Menjalankan web server, queue worker, dan llama-server (jika AI_SERVER_COMMAND diisi) dalam satu perintah')]
class SiprikaServe extends Command
{
    public function handle(): int
    {
        $php = (new PhpExecutableFinder)->find(false) ?: PHP_BINARY;
        $artisan = base_path('artisan');

        $processes = [
            'server' => new Process([$php, $artisan, 'serve', '--host='.$this->option('host'), '--port='.$this->option('port')], base_path(), null, null, null),
            // Satu worker supaya website diperiksa satu per satu sesuai urutan antrean
            'queue' => new Process([$php, $artisan, 'queue:listen', '--tries=1', '--timeout=0'], base_path(), null, null, null),
        ];

        $ai = $this->aiServer();

        if ($ai !== null) {
            $processes['ai'] = $ai;
        }

        foreach ($processes as $process) {
            $process->start();
        }

        $this->components->info("SIPRIKA berjalan di http://{$this->option('host')}:{$this->option('port')}  (Ctrl+C untuk berhenti)");

        while (true) {
            foreach ($processes as $name => $process) {
                $this->printOutput($name, $process->getIncrementalOutput().$process->getIncrementalErrorOutput());

                if ($process->isRunning()) {
                    continue;
                }

                // AI opsional: jika llama-server berhenti, scan tetap berjalan dengan teks katalog (bagian 9)
                if ($name === 'ai') {
                    $reason = trim((string) collect(preg_split('/\R/', trim($process->getErrorOutput())))->last());
                    $this->components->warn("llama-server berhenti (exit code {$process->getExitCode()}".($reason !== '' ? ": {$reason}" : '').'). Analisis AI memakai teks katalog. Periksa AI_SERVER_COMMAND.');
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
     * llama-server dijalankan hanya jika AI aktif, perintahnya diisi, dan port AI belum dipakai.
     */
    private function aiServer(): ?Process
    {
        $command = trim((string) config('siprika.ai.server_command'));

        if (! config('siprika.ai.enabled') || $command === '') {
            return null;
        }

        $url = parse_url((string) config('siprika.ai.url'));
        $socket = @fsockopen($url['host'] ?? '127.0.0.1', (int) ($url['port'] ?? 80), $errno, $errstr, 1);

        if ($socket !== false) {
            fclose($socket);
            $this->components->info('llama-server sudah berjalan di '.config('siprika.ai.url').', tidak dijalankan ulang.');

            return null;
        }

        $this->components->info('Menjalankan llama-server untuk analisis AI.');

        return new Process(ToolRunner::splitCommand($command), base_path(), null, null, null);
    }

    private function printOutput(string $name, string $output): void
    {
        foreach (preg_split('/\R/', trim($output)) as $line) {
            // Log llama-server sangat banyak, hanya status penting yang ditampilkan
            if ($line === '' || ($name === 'ai' && ! preg_match('/error|listening|model loaded|failed/i', $line))) {
                continue;
            }

            $this->line("<fg=gray>[{$name}]</> {$line}");
        }
    }
}
