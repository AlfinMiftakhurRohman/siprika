<?php

namespace App\Http\Controllers;

use App\Models\ScanTarget;
use App\Report\RawReportExporter;
use App\Risk\RiskRegisterExporter;
use App\Scanner\CatalogCoverage;
use App\Scanner\ScanQueue;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\View\View;
use Symfony\Component\HttpFoundation\BinaryFileResponse;

class ScanTargetController extends Controller
{
    public const TABS = [
        'overview' => 'Overview',
        'security' => 'Security Check',
        'findings' => 'Findings',
        'risk' => 'Risk Register',
        'coverage' => 'Coverage',
    ];

    public function show(Request $request, ScanTarget $scanTarget): View
    {
        // Nilai tab di luar daftar (termasuk bentuk array seperti ?tab[]=x) kembali ke Overview
        $tab = $request->query('tab');
        $tab = is_string($tab) && array_key_exists($tab, self::TABS) ? $tab : 'overview';

        $scanTarget->load(['batch', 'observations', 'findings.evidences', 'riskItems']);

        return view('targets.show', [
            'target' => $scanTarget,
            'tab' => $tab,
            'tabs' => self::TABS,
            'observations' => $scanTarget->observations->keyBy('check_key'),
            // Hanya untuk target yang sudah selesai; selama berjalan semua kunci masih belum diperiksa
            'catalogCoverage' => $scanTarget->status->isFinished() ? CatalogCoverage::for($scanTarget) : [],
        ]);
    }

    /**
     * Pindai ulang satu website dengan mode yang sama sebagai batch baru.
     */
    public function rescan(ScanTarget $scanTarget, ScanQueue $queue): RedirectResponse
    {
        if (! $scanTarget->status->isFinished()) {
            return redirect()->route('targets.show', $scanTarget)
                ->with('status', "{$scanTarget->host} masih dalam antrean atau sedang diperiksa. Pindai ulang dapat dilakukan setelah selesai.");
        }

        $batch = $queue->restart($scanTarget->batch->mode, [$scanTarget]);

        return redirect()->route('scans.show', $batch)
            ->with('status', "Pemindaian ulang {$scanTarget->host}. Hasil lama tetap tersimpan di Batch #{$scanTarget->scan_batch_id}.");
    }

    public function export(ScanTarget $scanTarget, RiskRegisterExporter $exporter): BinaryFileResponse
    {
        return $exporter->download($scanTarget->riskItems()->get(), "Risk Register SIPRIKA - {$scanTarget->host}.xlsx");
    }

    /**
     * Laporan mentah satu website: semua pemeriksaan, temuan, teknologi, dan hasil tool (bukan template).
     */
    public function rawReport(ScanTarget $scanTarget, RawReportExporter $exporter): BinaryFileResponse
    {
        return $exporter->download(collect([$scanTarget]), "Laporan Mentah SIPRIKA - {$scanTarget->host}.xlsx");
    }
}
