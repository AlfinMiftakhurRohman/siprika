<?php

namespace App\Scanner;

use App\Enums\ObservationStatus;
use App\Enums\ScanMode;
use App\Models\ScanTarget;
use App\Scanner\Checks\BackgroundCheck;
use App\Scanner\Checks\Check;
use App\Scanner\Checks\ExternalToolCheck;
use App\Scanner\Data\ObservationData;

/**
 * Progress per tahap pemeriksaan yang disimpan di scan_targets.progress (bagian 13).
 *
 * Setiap tahap punya bobot berupa perkiraan lamanya (config siprika.scan.expected_seconds),
 * supaya persentase bergerak wajar walaupun satu tahap (contoh Nuclei) jauh lebih lama dari yang lain.
 */
class ScanProgress
{
    public const WAITING = 'waiting';

    public const RUNNING = 'running';

    public const DONE = 'done';

    public const ERROR = 'error';

    public const SKIPPED = 'skipped';

    /**
     * background: tahap yang berjalan di latar belakang (Nuclei) bersamaan dengan tahap sesudahnya,
     * after_checks: tahap setelah semua pemeriksaan selesai (AI dan Risk Assessment).
     *
     * @var array<string, array{label: string, status: string, weight: int, started_at: float|null, finished_at?: float, background?: bool, after_checks?: bool}>
     */
    private array $steps = [];

    /**
     * @param  list<Check>  $checks
     */
    public function __construct(private ScanTarget $target, array $checks)
    {
        $mode = $target->batch->mode;

        foreach ($checks as $check) {
            // Tool eksternal yang belum dipasang selesai seketika (NOT ASSESSED)
            $weight = $check instanceof ExternalToolCheck && ! $check->isAvailable() ? 1 : self::expectedSeconds($check->key(), $mode);
            $this->steps[$check->key()] = self::step($check->label(), $weight, background: $check instanceof BackgroundCheck);
        }

        $this->steps['ai-analysis'] = self::step('AI Analysis', config('siprika.ai.enabled') ? self::expectedSeconds('ai-analysis', $mode) : 1, afterChecks: true);
        $this->steps['risk-assessment'] = self::step('Risk Assessment', self::expectedSeconds('risk-assessment', $mode), afterChecks: true);

        $this->save();
    }

    public function set(string $key, string $status): void
    {
        // Tahap yang tidak terdaftar tidak ditambahkan, supaya data progress tetap lengkap (label dan bobot)
        if (! isset($this->steps[$key])) {
            return;
        }

        $this->steps[$key]['status'] = $status;

        if ($status === self::RUNNING) {
            $this->steps[$key]['started_at'] = microtime(true);
        } elseif ($status !== self::WAITING) {
            // Jam selesai setiap tahap untuk rincian waktu di laporan mentah
            $this->steps[$key]['finished_at'] = microtime(true);
        }

        $this->save();
    }

    /**
     * Persentase dari waktu yang sudah berjalan dibanding perkiraan seluruh waktu (berjalan + sisa), sehingga selalu
     * sejalan dengan perkiraan sisa waktu. Maksimal 99, 100 hanya untuk target yang selesai. Sebelum ada tahap yang
     * mulai, dipakai bobot tahap yang sudah selesai.
     *
     * @param  list<array{status: string, weight?: int, started_at?: float|null, background?: bool, after_checks?: bool}>  $steps
     */
    public static function percent(array $steps, ?float $now = null): int
    {
        $now ??= microtime(true);
        $started = array_filter(array_map(fn (array $step) => $step['started_at'] ?? null, $steps));

        if ($started === []) {
            $total = array_sum(array_map(fn (array $step) => max(1, (int) ($step['weight'] ?? 1)), $steps));
            $done = array_sum(array_map(fn (array $step) => in_array($step['status'], [self::DONE, self::ERROR, self::SKIPPED], true) ? max(1, (int) ($step['weight'] ?? 1)) : 0, $steps));

            return $total === 0 ? 0 : (int) min(99, floor($done / $total * 100));
        }

        $elapsed = max(0, $now - min($started));
        $remaining = self::remainingSeconds($steps, $now);

        return $elapsed + $remaining <= 0 ? 99 : (int) min(99, floor($elapsed / ($elapsed + $remaining) * 100));
    }

    /**
     * Perkiraan sisa detik dari bobot (perkiraan lama) setiap tahap. Tahap latar belakang (Nuclei) berjalan bersamaan
     * dengan pemeriksaan sesudahnya, jadi yang dihitung adalah yang paling lama di antara keduanya; tahap AI dan Risk
     * Assessment menunggu keduanya selesai. Data progress lama tanpa tanda background dihitung berurutan.
     *
     * @param  list<array{status: string, weight?: int, started_at?: float|null, background?: bool, after_checks?: bool}>  $steps
     */
    public static function remainingSeconds(array $steps, ?float $now = null): int
    {
        $now ??= microtime(true);
        $sequential = 0.0;
        $background = 0.0;
        $parallel = 0.0;
        $backgroundStarted = false;

        foreach ($steps as $step) {
            $left = self::stepRemaining($step, $now);

            if (! empty($step['background'])) {
                $background += $left;
                $backgroundStarted = true;
            } elseif ($backgroundStarted && empty($step['after_checks'])) {
                $parallel += $left;
            } else {
                $sequential += $left;
            }
        }

        return (int) round($sequential + max($background, $parallel));
    }

    /**
     * Sisa satu tahap: bobot penuh jika menunggu, sisa bobot dari waktu berjalan (maksimal 95% terpakai) jika berjalan.
     *
     * @param  array{status: string, weight?: int, started_at?: float|null}  $step
     */
    private static function stepRemaining(array $step, float $now): float
    {
        $weight = max(1, (int) ($step['weight'] ?? 1));

        return match ($step['status']) {
            self::WAITING => $weight,
            self::RUNNING => (1 - min(0.95, (isset($step['started_at']) ? max(0, $now - $step['started_at']) : 0) / $weight)) * $weight,
            default => 0.0,
        };
    }

    /**
     * @param  list<ObservationData>  $observations
     */
    public static function fromObservations(array $observations): string
    {
        $statuses = array_map(fn (ObservationData $o) => $o->status, $observations);

        if (in_array(ObservationStatus::Error, $statuses, true)) {
            return self::ERROR;
        }

        if ($statuses !== [] && array_filter($statuses, fn ($s) => $s !== ObservationStatus::NotAssessed) === []) {
            return self::SKIPPED;
        }

        return self::DONE;
    }

    public static function label(string $status): string
    {
        return match ($status) {
            self::WAITING => 'Waiting...',
            self::RUNNING => 'Running...',
            self::DONE => '✓',
            self::ERROR => 'Error',
            self::SKIPPED => 'Tidak dijalankan',
            default => $status,
        };
    }

    public static function cssClass(string $status): string
    {
        return match ($status) {
            self::RUNNING => 'text-sky-700 font-medium',
            self::DONE => 'text-emerald-700',
            self::ERROR => 'text-amber-700',
            default => 'text-slate-400',
        };
    }

    private static function expectedSeconds(string $key, ScanMode $mode): int
    {
        $expected = config("siprika.scan.expected_seconds.{$key}", 1);

        return max(1, (int) (is_array($expected) ? ($expected[$mode->value] ?? 1) : $expected));
    }

    /**
     * @return array{label: string, status: string, weight: int, started_at: float|null, background?: bool, after_checks?: bool}
     */
    private static function step(string $label, int $weight, bool $background = false, bool $afterChecks = false): array
    {
        return ['label' => $label, 'status' => self::WAITING, 'weight' => $weight, 'started_at' => null]
            + array_filter(['background' => $background, 'after_checks' => $afterChecks]);
    }

    private function save(): void
    {
        $this->target->progress = array_map(
            fn (string $key, array $step) => ['key' => $key] + $step,
            array_keys($this->steps),
            $this->steps,
        );
        $this->target->save();
    }
}
