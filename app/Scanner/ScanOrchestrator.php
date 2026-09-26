<?php

namespace App\Scanner;

use App\Ai\AiAnalyzer;
use App\Enums\ObservationStatus;
use App\Enums\ScanMode;
use App\Enums\ScanTargetStatus;
use App\Models\ScanTarget;
use App\Risk\RiskEngine;
use App\Scanner\Checks\Check;
use App\Scanner\Network\SafeHttpClient;
use Illuminate\Support\Facades\Log;
use Throwable;

/**
 * Menjalankan pemeriksaan sesuai mode (Cepat atau Standar) untuk satu website secara berurutan.
 * Jika satu pemeriksaan gagal, pemeriksaan lain tetap dilanjutkan (bagian 13).
 */
class ScanOrchestrator
{
    public function __construct(
        private FindingRecorder $recorder,
        private AiAnalyzer $ai,
        private RiskEngine $riskEngine,
    ) {}

    public function run(ScanTarget $target): void
    {
        $mode = $target->batch->mode;
        $context = new ScanContext($target, app(SafeHttpClient::class), microtime(true) + $mode->timeout(), $mode);
        /** @var list<Check> $checks */
        $checks = array_map(fn (string $class) => app($class), $mode->checks());
        $progress = new ScanProgress($target, $checks);

        Log::info('SIPRIKA mulai memeriksa', ['target' => $target->url, 'mode' => $mode->value]);

        $abortReason = $this->runChecks($context, $checks, $progress);
        $target->overview = $context->overview;

        if ($abortReason !== null) {
            $this->markFailed($target, $progress, $abortReason);

            return;
        }

        $this->recordSkippedByMode($target, $mode);
        $this->recorder->record($target, $context->findings);
        $this->analyzeWithAi($target, $progress);
        $this->assessRisk($target, $progress);
        $this->markFinished($target);
    }

    /**
     * Jalankan pemeriksaan berurutan. Setelah target dihentikan (contoh DNS gagal), sisanya dilewati.
     *
     * @param  list<Check>  $checks
     * @return string|null alasan jika target tidak dapat diperiksa lebih lanjut
     */
    private function runChecks(ScanContext $context, array $checks, ScanProgress $progress): ?string
    {
        $abortReason = null;

        foreach ($checks as $check) {
            if ($abortReason !== null) {
                $progress->set($check->key(), ScanProgress::SKIPPED);

                continue;
            }

            $before = count($context->observations);
            $progress->set($check->key(), ScanProgress::RUNNING);

            $abortReason = $this->runCheck($context, $check);

            $new = array_slice($context->observations, $before);
            $this->persistObservations($context->target, $new);
            $progress->set($check->key(), $abortReason !== null ? ScanProgress::ERROR : ScanProgress::fromObservations($new));
        }

        return $abortReason;
    }

    /**
     * Kesalahan tak terduga dicatat ERROR tanpa menghentikan pemeriksaan lain (bagian 13).
     *
     * @return string|null alasan jika pemeriksaan ini menghentikan target
     */
    private function runCheck(ScanContext $context, Check $check): ?string
    {
        if ($context->remainingSeconds() <= 0) {
            $context->observe($check->key(), $check->label(), 'internal', ObservationStatus::Error, 'Tidak dijalankan karena pemeriksaan website melewati batas waktu.');

            return null;
        }

        try {
            $check->run($context);
        } catch (TargetAborted $e) {
            return $e->getMessage();
        } catch (Throwable $e) {
            report($e);
            $context->observe($check->key(), $check->label(), 'internal', ObservationStatus::Error, 'Pemeriksaan gagal: '.mb_substr($e->getMessage(), 0, 300));
        }

        return null;
    }

    private function markFailed(ScanTarget $target, ScanProgress $progress, string $reason): void
    {
        $progress->set('ai-analysis', ScanProgress::SKIPPED);
        $progress->set('risk-assessment', ScanProgress::SKIPPED);

        $target->status = ScanTargetStatus::Failed;
        $target->error_message = $reason;
        $target->save();

        Log::info('SIPRIKA target gagal diperiksa', ['target' => $target->url, 'reason' => $reason]);
    }

    private function analyzeWithAi(ScanTarget $target, ScanProgress $progress): void
    {
        $progress->set('ai-analysis', ScanProgress::RUNNING);
        $ai = $this->ai->analyze($target);

        $target->observations()->create([
            'check_key' => 'ai-analysis',
            'label' => 'AI Risk Analysis',
            'tool' => 'ai',
            'status' => match ($ai['status']) {
                'disabled' => ObservationStatus::NotAssessed,
                'error' => ObservationStatus::Error,
                default => ObservationStatus::Info,
            },
            'summary' => $ai['summary'],
            'raw' => $ai['raw'],
        ]);

        $progress->set('ai-analysis', match ($ai['status']) {
            'disabled' => ScanProgress::SKIPPED,
            'error' => ScanProgress::ERROR,
            default => ScanProgress::DONE,
        });
    }

    private function assessRisk(ScanTarget $target, ScanProgress $progress): void
    {
        $progress->set('risk-assessment', ScanProgress::RUNNING);
        $this->riskEngine->assess($target);
        $progress->set('risk-assessment', ScanProgress::DONE);
    }

    /**
     * PARTIAL jika ada pemeriksaan ERROR. Kegagalan AI tidak dihitung karena hasil teknis tetap lengkap.
     */
    private function markFinished(ScanTarget $target): void
    {
        $hasError = $target->observations()->where('status', ObservationStatus::Error->value)->where('tool', '!=', 'ai')->exists();

        $target->status = $hasError ? ScanTargetStatus::Partial : ScanTargetStatus::Completed;
        $target->save();

        Log::info('SIPRIKA selesai memeriksa', ['target' => $target->url, 'status' => $target->status->value]);
    }

    /**
     * Pemeriksaan yang hanya ada di Mode Standar dicatat NOT ASSESSED supaya batasan Mode Cepat terlihat di Coverage (bagian 22.8).
     */
    private function recordSkippedByMode(ScanTarget $target, ScanMode $mode): void
    {
        foreach ($mode->skippedChecks() as $class) {
            /** @var Check $check */
            $check = app($class);

            $target->observations()->create([
                'check_key' => $check->key(),
                'label' => $check->label(),
                'tool' => '-',
                'status' => ObservationStatus::NotAssessed,
                'summary' => "Tidak dijalankan pada Mode {$mode->label()}, hanya tersedia pada Mode Standar.",
            ]);
        }
    }

    /**
     * @param  list<Data\ObservationData>  $observations
     */
    private function persistObservations(ScanTarget $target, array $observations): void
    {
        foreach ($observations as $observation) {
            $target->observations()->create([
                'check_key' => $observation->key,
                'label' => $observation->label,
                'tool' => $observation->tool,
                'status' => $observation->status,
                'summary' => $observation->summary !== null ? mb_substr($observation->summary, 0, 2000) : null,
                'raw' => $observation->raw,
            ]);
        }
    }
}
