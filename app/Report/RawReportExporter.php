<?php

namespace App\Report;

use App\Models\ScanFinding;
use App\Models\ScanObservation;
use App\Models\ScanTarget;
use App\Scanner\CatalogCoverage;
use App\Scanner\ScanProgress;
use App\Support\Duration;
use App\Support\SourceLabel;
use Carbon\Carbon;
use Illuminate\Database\Eloquent\Collection as EloquentCollection;
use Illuminate\Support\Collection;
use PhpOffice\PhpSpreadsheet\Cell\Coordinate;
use PhpOffice\PhpSpreadsheet\Cell\DataType;
use PhpOffice\PhpSpreadsheet\Spreadsheet;
use PhpOffice\PhpSpreadsheet\Style\Alignment;
use PhpOffice\PhpSpreadsheet\Style\Fill;
use PhpOffice\PhpSpreadsheet\Worksheet\Worksheet;
use PhpOffice\PhpSpreadsheet\Writer\Xlsx;
use Symfony\Component\HttpFoundation\BinaryFileResponse;

/**
 * Laporan mentah: semua yang diperiksa dan ditemukan SIPRIKA (tahap, pemeriksaan, temuan dan bukti, teknologi,
 * port, hasil setiap tool, coverage) dalam file Excel sendiri. Dibuat dari nol, template Risk Register tidak dibaca
 * maupun diubah. Isi dari website target selalu ditulis sebagai teks supaya tidak dijalankan Excel sebagai rumus.
 */
class RawReportExporter
{
    /** Batas isi satu sel Excel 32.767 karakter */
    private const MAX_CELL_LENGTH = 32000;

    private const DATE_FORMAT = 'd-m-Y H:i:s';

    private const STEP_STATUS = [
        ScanProgress::WAITING => 'Menunggu',
        ScanProgress::RUNNING => 'Berjalan',
        ScanProgress::DONE => 'Selesai',
        ScanProgress::ERROR => 'Error',
        ScanProgress::SKIPPED => 'Tidak dijalankan',
    ];

    /**
     * @param  Collection<int, ScanTarget>  $targets
     */
    public function export(Collection $targets, string $destination): void
    {
        $targets = EloquentCollection::make($targets->values()->all())->loadMissing(['batch', 'observations', 'findings.evidences']);

        $spreadsheet = new Spreadsheet;
        $spreadsheet->getProperties()->setCreator('SIPRIKA')->setTitle('Laporan Mentah SIPRIKA');
        $spreadsheet->removeSheetByIndex(0);

        foreach ($this->sheets($targets) as $title => [$columns, $rows]) {
            $this->addSheet($spreadsheet, $title, $columns, $rows);
        }

        $spreadsheet->setActiveSheetIndex(0);
        (new Xlsx($spreadsheet))->save($destination);
        $spreadsheet->disconnectWorksheets();
    }

    /**
     * Export ke file sementara untuk diunduh. File dihapus setelah terkirim.
     *
     * @param  Collection<int, ScanTarget>  $targets
     */
    public function download(Collection $targets, string $filename): BinaryFileResponse
    {
        $base = tempnam(sys_get_temp_dir(), 'siprika');
        @unlink($base);
        $path = $base.'.xlsx';

        $this->export($targets, $path);

        return response()->download($path, $filename)->deleteFileAfterSend();
    }

    /**
     * Nama sheet => [kolom (judul => lebar), baris].
     *
     * @param  Collection<int, ScanTarget>  $targets
     * @return array<string, array{0: array<string, int>, 1: list<list<string|int|float|null>>}>
     */
    private function sheets(Collection $targets): array
    {
        $each = fn (callable $rows) => $targets->flatMap(fn (ScanTarget $target) => $rows($target))->values()->all();

        return [
            'Ringkasan' => [[
                'No' => 5, 'Website' => 36, 'Mode' => 10, 'Status' => 15, 'Mulai' => 20, 'Selesai' => 20, 'Durasi' => 18,
                'IP Address' => 22, 'URL Final' => 36, 'HTTP Status' => 8, 'HTTPS' => 8, 'Redirect' => 40, 'Title' => 30,
                'Web Server' => 18, 'X-Powered-By' => 16, 'CDN/WAF' => 14, 'CMS' => 12, 'Protokol TLS' => 16,
                'Penerbit Sertifikat' => 24, 'Sertifikat Berlaku Hingga' => 14, 'Port Terbuka' => 30,
                'Kerawanan' => 10, 'Informasi' => 10, 'Pesan Error' => 40,
            ], $targets->map(fn (ScanTarget $target, int $index) => $this->summaryRow($target, $index + 1))->all()],

            'Tahap' => [
                ['Website' => 36, 'No' => 5, 'Tahap' => 28, 'Status' => 12, 'Mulai' => 20, 'Selesai' => 20, 'Lama' => 18],
                $each($this->stepRows(...)),
            ],

            'Pemeriksaan' => [
                ['Website' => 36, 'Pemeriksaan' => 28, 'Kunci' => 24, 'Tool' => 18, 'Status' => 14, 'Ringkasan' => 90],
                $each(fn (ScanTarget $target) => $target->observations->sortBy('id')->map(fn (ScanObservation $observation) => [
                    $target->url, $observation->label, $observation->check_key, SourceLabel::of($observation->tool),
                    $observation->status->value, $observation->summary,
                ])),
            ],

            'Temuan & Bukti' => [
                ['Website' => 36, 'Kunci' => 30, 'Judul' => 40, 'Jenis' => 11, 'Severity' => 9, 'Sumber Temuan' => 28, 'Sumber Bukti' => 18, 'Endpoint' => 40, 'Bukti' => 80],
                $each($this->findingRows(...)),
            ],

            'Teknologi' => [
                ['Website' => 36, 'Teknologi' => 26, 'Versi' => 12, 'Kategori' => 24, 'Sumber' => 18],
                $each(fn (ScanTarget $target) => collect($target->overview['technologies'] ?? [])->map(fn (array $technology) => [
                    $target->url, $technology['name'] ?? null, $technology['version'] ?? null, $technology['category'] ?? null,
                    SourceLabel::of((string) ($technology['source'] ?? '')),
                ])),
            ],

            'Port & Layanan' => [
                ['Website' => 36, 'IP' => 18, 'Port' => 8, 'Layanan' => 16, 'Produk' => 28, 'Versi' => 14],
                $each(fn (ScanTarget $target) => collect($this->toolRaw($target, 'nmap', 'services'))->unique('port')->map(fn (array $service) => [
                    $target->url, $this->toolRaw($target, 'nmap', 'ip') ?: null, $service['port'] ?? null,
                    $service['service'] ?? null, $service['product'] ?? null, $service['version'] ?? null,
                ])),
            ],

            // Keluaran mentah tool; kolom terakhir menjelaskan hasil mana yang menjadi temuan dan mana yang tidak dipakai
            'Nuclei' => [
                ['Website' => 36, 'Template' => 44, 'Nama' => 44, 'Severity' => 9, 'Lokasi' => 44, 'Dipakai sebagai' => 50],
                $each(fn (ScanTarget $target) => collect($this->toolRaw($target, 'nuclei', 'results'))->map(fn (array $result) => [
                    $target->url, $result['template'] ?? null, $result['name'] ?? null, $result['severity'] ?? null, $result['matched_at'] ?? null,
                    $this->nucleiUsage($target, $result),
                ])),
            ],

            'OWASP ZAP' => [
                ['Website' => 36, 'Alert' => 44, 'Risk' => 13, 'URL' => 44, 'Parameter' => 20, 'Evidence' => 40, 'Plugin' => 9, 'Dipakai sebagai' => 50],
                $each(fn (ScanTarget $target) => collect($this->toolRaw($target, 'zap', 'alerts'))->map(fn (array $alert) => [
                    $target->url, $alert['name'] ?? null, $alert['risk'] ?? null, $alert['url'] ?? null,
                    $alert['param'] ?? null, $alert['evidence'] ?? null, $alert['plugin'] ?? null,
                    $this->zapUsage($target, $alert),
                ])),
            ],

            'testssl.sh' => [
                ['Website' => 36, 'Item' => 26, 'Hasil' => 60, 'Severity' => 10],
                $each(fn (ScanTarget $target) => collect($this->toolRaw($target, 'testssl', 'items'))->map(fn (array $item) => [
                    $target->url, $item['id'] ?? null, $item['finding'] ?? null, $item['severity'] ?? null,
                ])),
            ],

            // Coverage hanya berarti setelah pemeriksaan selesai; selama berjalan semua kunci belum diperiksa
            'Coverage' => [
                ['Website' => 36, 'Kunci' => 28, 'Judul' => 40, 'Status' => 14, 'Pemeriksa' => 40, 'Keterangan' => 70],
                $each(fn (ScanTarget $target) => $target->status->isFinished() ? collect(CatalogCoverage::for($target))->map(fn (array $row) => [
                    $target->url, $row['key'], $row['title'], $row['status']->value, implode(', ', $row['assessors']), $row['note'],
                ]) : []),
            ],
        ];
    }

    /**
     * @return list<string|int|null>
     */
    private function summaryRow(ScanTarget $target, int $number): array
    {
        $overview = $target->overview ?? [];
        $tls = $overview['tls'] ?? [];
        $informational = $target->findings->filter(fn (ScanFinding $finding) => $finding->isInformational())->count();

        return [
            $number,
            $target->url,
            $target->batch->mode->label(),
            $target->status->label(),
            $target->started_at?->format(self::DATE_FORMAT),
            $target->finished_at?->format(self::DATE_FORMAT),
            $target->finished_at !== null && $target->elapsedSeconds() !== null ? Duration::format($target->elapsedSeconds()) : null,
            $this->text($overview['ip_addresses'] ?? null),
            $overview['final_url'] ?? null,
            $overview['http_status'] ?? null,
            match ($overview['https'] ?? null) {
                true => 'Ya', false => 'Tidak', default => null
            },
            match (true) {
                ! isset($overview['redirect_chain']) => null,
                count($overview['redirect_chain']) < 2 => 'Tidak ada',
                default => collect($overview['redirect_chain'])->map(fn (array $hop) => ($hop['status'] ?? '?').' '.($hop['url'] ?? ''))->implode(' -> '),
            },
            $overview['title'] ?? null,
            $overview['web_server'] ?? null,
            $overview['powered_by'] ?? null,
            $this->text($overview['cdn'] ?? null),
            $this->text($overview['cms'] ?? null),
            $this->text($overview['tls_protocols'] ?? ($tls['protocol'] ?? null)),
            $tls['issuer'] ?? null,
            $tls['valid_to'] ?? null,
            collect($overview['open_ports'] ?? [])->map(fn (array $port) => trim(($port['port'] ?? '').'/'.($port['service'] ?? '').' '.($port['product'] ?? '')))->implode(', ') ?: null,
            $target->findings->count() - $informational,
            $informational,
            $target->error_message,
        ];
    }

    /**
     * Tahap pemeriksaan dengan jam mulai, jam selesai, dan lamanya (jam selesai tercatat sejak 28-09-2026).
     *
     * @return list<list<string|int|null>>
     */
    private function stepRows(ScanTarget $target): array
    {
        $rows = [];

        foreach (array_values($target->progress ?? []) as $index => $step) {
            $started = isset($step['started_at']) ? (float) $step['started_at'] : null;
            $finished = isset($step['finished_at']) ? (float) $step['finished_at'] : null;

            $rows[] = [
                $target->url,
                $index + 1,
                $step['label'] ?? $step['key'] ?? null,
                self::STEP_STATUS[$step['status'] ?? ''] ?? ($step['status'] ?? null),
                $this->time($started),
                $this->time($finished),
                $started !== null && $finished !== null ? Duration::format((int) round($finished - $started)) : null,
            ];
        }

        return $rows;
    }

    /**
     * Satu baris per bukti; temuan tanpa bukti tetap satu baris.
     *
     * @return list<list<string|null>>
     */
    private function findingRows(ScanTarget $target): array
    {
        $rows = [];

        foreach ($target->findings->sortByDesc(fn (ScanFinding $finding) => $finding->severity->rank()) as $finding) {
            $base = [
                $target->url,
                $finding->finding_key,
                $finding->title,
                $finding->isInformational() ? 'Informasi' : 'Kerawanan',
                $finding->severity->label(),
                SourceLabel::list($finding->sources ?? []),
            ];

            if ($finding->evidences->isEmpty()) {
                $rows[] = [...$base, null, null, null];
            }

            foreach ($finding->evidences as $evidence) {
                $rows[] = [...$base, SourceLabel::of($evidence->source), $evidence->endpoint, $evidence->detail];
            }
        }

        return $rows;
    }

    /**
     * Hasil Nuclei menjadi temuan apa, dicocokkan lewat template yang tersimpan di bukti temuan, atau alasan tidak dipakai.
     *
     * @param  array<string, mixed>  $result
     */
    private function nucleiUsage(ScanTarget $target, array $result): string
    {
        $template = (string) ($result['template'] ?? '');
        $finding = $this->findingWithEvidence($target, 'nuclei', fn (array $raw) => ($raw['template'] ?? null) === $template);

        if ($finding !== null) {
            return self::findingUsage($finding);
        }

        $id = explode(':', $template)[0];

        if (in_array($id, config('siprika_scanner.nuclei_raw_only', []), true)) {
            return 'Tidak dipakai: template heuristik yang sering keliru (CDN/WAF memakai deteksi bawaan)';
        }

        $map = config('siprika_scanner.nuclei_map', []);
        $key = $map[$template] ?? $map[$id] ?? null;
        $ignored = $this->toolRaw($target, 'nuclei', 'ignored_keys');

        return $key !== null && isset($ignored[$key])
            ? "Diabaikan untuk {$key}: {$ignored[$key]}"
            : 'Bukan temuan (deteksi teknologi atau informasi yang tidak dinilai)';
    }

    /**
     * Alert ZAP menjadi temuan apa, dicocokkan lewat alert_ref yang tersimpan di bukti temuan, atau alasan tidak dipakai.
     *
     * @param  array<string, mixed>  $alert
     */
    private function zapUsage(ScanTarget $target, array $alert): string
    {
        $reference = (string) ($alert['ref'] ?? $alert['plugin'] ?? '');
        $finding = $this->findingWithEvidence($target, 'zap', fn (array $raw) => (string) ($raw['alert_ref'] ?? $raw['plugin'] ?? '') === $reference);

        if ($finding !== null) {
            return self::findingUsage($finding);
        }

        $map = config('siprika_scanner.zap_map', []);
        $key = $map[$reference] ?? $map[(string) ($alert['plugin'] ?? '')] ?? null;
        $ignored = $this->toolRaw($target, 'zap', 'ignored_keys');

        return match (true) {
            $key !== null && isset($ignored[$key]) => "Diabaikan untuk {$key}: {$ignored[$key]}",
            $key !== null => "Tidak menjadi temuan {$key} (kriteria SIPRIKA tidak terpenuhi)",
            default => 'Informasi ZAP di luar katalog SIPRIKA',
        };
    }

    /**
     * @param  callable(array<string, mixed>): bool  $matches
     */
    private function findingWithEvidence(ScanTarget $target, string $source, callable $matches): ?ScanFinding
    {
        return $target->findings->first(fn (ScanFinding $finding) => $finding->evidences->contains(
            fn ($evidence) => $evidence->source === $source && $matches((array) $evidence->raw),
        ));
    }

    private static function findingUsage(ScanFinding $finding): string
    {
        return ($finding->isInformational() ? 'Informasi' : 'Temuan').": {$finding->finding_key}";
    }

    /**
     * Nilai raw hasil tool dari observation-nya, contoh daftar alert ZAP.
     */
    private function toolRaw(ScanTarget $target, string $tool, string $key): mixed
    {
        $value = $target->observations
            ->filter(fn (ScanObservation $observation) => $observation->tool === $tool && isset($observation->raw[$key]))
            ->first()?->raw[$key];

        return $value ?? ($key === 'ip' ? null : []);
    }

    private function time(?float $timestamp): ?string
    {
        return $timestamp === null ? null : Carbon::createFromTimestamp($timestamp, config('app.timezone'))->format(self::DATE_FORMAT);
    }

    private function text(mixed $value): ?string
    {
        if (is_array($value)) {
            $value = implode(', ', array_map(fn ($item) => is_array($item) ? json_encode($item, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) : (string) $item, $value));
        }

        return $value === null || $value === '' ? null : (string) $value;
    }

    /**
     * @param  array<string, int>  $columns  judul kolom => lebar
     * @param  list<list<string|int|float|null>>  $rows
     */
    private function addSheet(Spreadsheet $spreadsheet, string $title, array $columns, array $rows): void
    {
        $sheet = $spreadsheet->createSheet();
        $sheet->setTitle($title);
        $lastColumn = Coordinate::stringFromColumnIndex(count($columns));

        foreach (array_keys($columns) as $index => $header) {
            $letter = Coordinate::stringFromColumnIndex($index + 1);
            $sheet->setCellValueExplicit("{$letter}1", $header, DataType::TYPE_STRING);
            $sheet->getColumnDimension($letter)->setWidth($columns[$header]);
        }

        $header = $sheet->getStyle("A1:{$lastColumn}1");
        $header->getFont()->setBold(true)->getColor()->setARGB('FFFFFFFF');
        $header->getFill()->setFillType(Fill::FILL_SOLID)->getStartColor()->setARGB('FF1E293B');
        $sheet->freezePane('A2');

        if ($rows === []) {
            $sheet->setCellValueExplicit('A2', '(tidak ada data)', DataType::TYPE_STRING);

            return;
        }

        foreach ($rows as $rowIndex => $row) {
            foreach (array_values($row) as $columnIndex => $value) {
                $this->writeCell($sheet, Coordinate::stringFromColumnIndex($columnIndex + 1).($rowIndex + 2), $value);
            }
        }

        $lastRow = count($rows) + 1;
        $sheet->setAutoFilter("A1:{$lastColumn}{$lastRow}");
        $sheet->getStyle("A2:{$lastColumn}{$lastRow}")->getAlignment()->setVertical(Alignment::VERTICAL_TOP)->setWrapText(true);
    }

    private function writeCell(Worksheet $sheet, string $coordinate, mixed $value): void
    {
        if ($value === null || $value === '') {
            return;
        }

        if (is_int($value) || is_float($value)) {
            $sheet->setCellValueExplicit($coordinate, $value, DataType::TYPE_NUMERIC);

            return;
        }

        // Karakter kontrol tidak sah di XML Excel; isi sangat panjang dipotong sesuai batas sel
        $text = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', (string) $value) ?? '';
        $text = mb_strlen($text) > self::MAX_CELL_LENGTH ? mb_substr($text, 0, self::MAX_CELL_LENGTH).' ... (dipotong)' : $text;

        $sheet->setCellValueExplicit($coordinate, $text, DataType::TYPE_STRING);
    }
}
