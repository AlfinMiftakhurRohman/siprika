<?php

namespace App\Scanner\Tools;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Process;

/**
 * Menjalankan tool eksternal dari perintah di .env.
 */
class ToolRunner
{
    /**
     * Perintah tool dari config sebagai daftar argumen.
     *
     * @return list<string>|null null jika tool belum diatur
     */
    public function command(string $tool): ?array
    {
        $command = trim((string) config("siprika.tools.{$tool}.command"));

        return $command === '' ? null : self::splitCommand($command);
    }

    /**
     * Pecah perintah menjadi argumen. Mendukung prefix seperti "wsl -d Ubuntu -e testssl.sh"
     * dan path berspasi yang diberi tanda kutip ganda.
     *
     * @return list<string>
     */
    public static function splitCommand(string $command): array
    {
        return array_values(array_filter(str_getcsv(trim($command), ' ', '"', ''), fn ($part) => $part !== null && $part !== ''));
    }

    /**
     * Jalankan tool dan tunggu sampai selesai.
     *
     * @param  list<string>  $arguments
     */
    public function run(string $tool, array $arguments, int $timeout, ?string $workingDirectory = null): ToolResult
    {
        return $this->start($tool, $arguments, $timeout, $workingDirectory)->wait();
    }

    /**
     * Mulai tool di latar belakang. Hasilnya dibaca dengan RunningTool::wait().
     *
     * @param  list<string>  $arguments
     */
    public function start(string $tool, array $arguments, int $timeout, ?string $workingDirectory = null): RunningTool
    {
        $command = [...($this->command($tool) ?? []), ...$arguments];

        Log::info('SIPRIKA menjalankan tool', ['tool' => $tool, 'command' => implode(' ', $command)]);

        $pending = Process::timeout(max(1, $timeout));

        if ($workingDirectory !== null) {
            $pending = $pending->path($workingDirectory);
        }

        return new RunningTool($pending->start($command));
    }
}
