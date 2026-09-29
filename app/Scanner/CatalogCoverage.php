<?php

namespace App\Scanner;

use App\Enums\ObservationStatus;
use App\Models\ScanObservation;
use App\Models\ScanTarget;
use App\Support\SourceLabel;
use Illuminate\Support\Collection;

/**
 * Status setiap kunci katalog bagian 23.1 untuk satu website (bagian 22.10).
 *
 * Pemeriksa sebuah kunci adalah pemeriksaan bawaan di config siprika_scanner.catalog_coverage ditambah
 * tool eksternal yang mencantumkan kunci itu di raw.assessed_keys. Status kunci:
 * - FAIL jika ada finding;
 * - PASS jika minimal satu pemeriksa berhasil menilai tanpa temuan;
 * - N/A jika kunci tidak berlaku, contoh HSTS pada website yang tidak punya HTTPS;
 * - ERROR jika pemeriksanya gagal;
 * - NOT ASSESSED jika tidak ada pemeriksa yang menilai (profil mode, tool tidak tersedia, WAF, redirect).
 * Kunci yang tidak diperiksa tidak pernah dianggap PASS.
 */
class CatalogCoverage
{
    /**
     * @return list<array{key: string, title: string, status: ObservationStatus, assessors: list<string>, note: string}>
     */
    public static function for(ScanTarget $target): array
    {
        $findings = $target->findings->keyBy('finding_key');
        // Port 443 menolak koneksi sementara http:// normal (finding no-https): kunci HTTPS tidak berlaku
        $httpsRefused = $target->observations->firstWhere('check_key', 'https')?->status === ObservationStatus::Fail;
        $rows = [];

        foreach (config('siprika_scanner.catalog_coverage', []) as $key => $builtin) {
            $assessors = $target->observations
                ->filter(fn (ScanObservation $o) => in_array($o->check_key, $builtin, true) || in_array($key, $o->raw['assessed_keys'] ?? [], true))
                ->values();
            $finding = $findings->get($key);
            $httpsOnly = $httpsRefused && in_array($key, config('siprika_scanner.https_keys', []), true);
            $status = match (true) {
                $finding !== null => ObservationStatus::Fail,
                $httpsOnly => ObservationStatus::NotApplicable,
                default => self::resolve($assessors),
            };

            $rows[] = [
                'key' => $key,
                'title' => (string) config("siprika_catalog.{$key}.title", $key),
                'status' => $status,
                'assessors' => $assessors->map(fn (ScanObservation $o) => $o->label)->unique()->values()->all(),
                'note' => match (true) {
                    $finding !== null => 'Ditemukan oleh: '.SourceLabel::list($finding->sources).'.',
                    $httpsOnly => 'HTTPS tidak tersedia pada website ini, kunci ini hanya berlaku pada HTTPS. Risikonya tercatat sebagai no-https.',
                    default => self::note($status, $assessors, $target),
                },
            ];
        }

        return $rows;
    }

    /**
     * Jumlah kunci yang belum terbukti aman karena tidak diperiksa atau pemeriksaannya gagal.
     *
     * @param  list<array{status: ObservationStatus}>  $rows
     */
    public static function unassessedCount(array $rows): int
    {
        return count(array_filter($rows, fn (array $row) => in_array($row['status'], [ObservationStatus::NotAssessed, ObservationStatus::Error], true)));
    }

    /**
     * @param  Collection<int, ScanObservation>  $assessors
     */
    private static function resolve(Collection $assessors): ObservationStatus
    {
        $statuses = $assessors->pluck('status');

        return match (true) {
            // FAIL pada observation tanpa finding kunci ini berarti temuannya untuk kunci lain (contoh Nuclei)
            $statuses->contains(fn (ObservationStatus $s) => in_array($s, [ObservationStatus::Pass, ObservationStatus::Info, ObservationStatus::Fail], true)) => ObservationStatus::Pass,
            $statuses->contains(ObservationStatus::NotApplicable) => ObservationStatus::NotApplicable,
            $statuses->contains(ObservationStatus::Error) => ObservationStatus::Error,
            default => ObservationStatus::NotAssessed,
        };
    }

    /**
     * Keterangan dari pemeriksa yang menentukan status.
     *
     * @param  Collection<int, ScanObservation>  $assessors
     */
    private static function note(ObservationStatus $status, Collection $assessors, ScanTarget $target): string
    {
        $deciding = $status === ObservationStatus::Pass
            ? $assessors->first(fn (ScanObservation $o) => $o->status !== ObservationStatus::NotAssessed)
            : $assessors->first(fn (ScanObservation $o) => $o->status === $status);

        // Ringkasan tool eksternal mencakup banyak kunci, jadi untuk PASS cukup disebut tidak ada temuan
        if ($deciding !== null && $status === ObservationStatus::Pass && isset($deciding->raw['assessed_keys'])) {
            return "{$deciding->label} menilai kunci ini dan tidak menemukan masalah.";
        }

        if ($deciding !== null) {
            return "{$deciding->label}: {$deciding->summary}";
        }

        if ($assessors->isNotEmpty()) {
            return $assessors->map(fn (ScanObservation $o) => "{$o->label}: {$o->summary}")->implode(' ');
        }

        return 'Tidak ada pemeriksaan yang menilai kunci ini pada Mode '.$target->batch->mode->label()
            .', karena tidak tercakup profil mode atau tool-nya belum dipasang.';
    }
}
