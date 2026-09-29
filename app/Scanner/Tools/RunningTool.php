<?php

namespace App\Scanner\Tools;

use Closure;
use Illuminate\Contracts\Process\InvokedProcess;
use Illuminate\Process\Exceptions\ProcessTimedOutException;

/**
 * Tool eksternal yang sedang berjalan di latar belakang (ToolRunner::start).
 */
class RunningTool
{
    private float $startedAt;

    private ?float $finishedAt = null;

    /**
     * @param  InvokedProcess|Closure(): ToolResult  $process  proses, atau hasil yang sudah jadi (dipakai test)
     */
    public function __construct(private InvokedProcess|Closure $process)
    {
        $this->startedAt = microtime(true);
    }

    /**
     * Baca output yang sudah ada tanpa menunggu. Dipanggil berkala supaya buffer output tidak penuh
     * dan proses tidak tertahan, serta supaya waktu selesainya tercatat walaupun hasilnya dibaca belakangan.
     */
    public function poll(): void
    {
        if ($this->process instanceof InvokedProcess && $this->finishedAt === null && ! $this->process->running()) {
            $this->finishedAt = microtime(true);
        }
    }

    public function wait(): ToolResult
    {
        if ($this->process instanceof Closure) {
            return ($this->process)();
        }

        try {
            $result = $this->process->wait();
        } catch (ProcessTimedOutException $e) {
            // Output yang sudah terkumpul sebelum batas waktu tetap dikembalikan supaya evidence tidak hilang
            return new ToolResult(false, $e->result->output(), $e->result->errorOutput(), null, true, $this->seconds());
        }

        return new ToolResult($result->successful(), $result->output(), $result->errorOutput(), $result->exitCode(), false, $this->seconds());
    }

    /**
     * Lama proses berjalan, sampai saat proses selesai (bukan saat hasilnya dibaca).
     */
    private function seconds(): float
    {
        $this->finishedAt ??= microtime(true);

        return $this->finishedAt - $this->startedAt;
    }
}
