<?php

namespace App\Http\Controllers;

use App\Enums\ScanMode;
use App\Enums\ScanTargetStatus;
use App\Http\Requests\StoreScanRequest;
use App\Jobs\ProcessScanTarget;
use App\Models\ScanBatch;
use App\Models\ScanTarget;
use App\Risk\RiskRegisterExporter;
use App\Support\TargetUrlNormalizer;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\DB;
use Illuminate\View\View;
use Symfony\Component\HttpFoundation\BinaryFileResponse;

class ScanController extends Controller
{
    public function create(): View
    {
        return view('scans.create', [
            'modes' => ScanMode::cases(),
            'defaultMode' => ScanMode::Standard,
            'allowsAllDomains' => TargetUrlNormalizer::fromConfig()->allowsAllDomains(),
            'recentBatches' => ScanBatch::withCount('targets')->latest('id')->limit(10)->get(),
        ]);
    }

    public function store(StoreScanRequest $request): RedirectResponse
    {
        $batch = DB::transaction(function () use ($request) {
            $batch = ScanBatch::create(['mode' => $request->mode()]);

            // Urutan antrean mengikuti urutan baris input
            $position = 1;

            foreach ($request->targets() as $target) {
                $batch->targets()->create([
                    'position' => $position++,
                    'url' => $target['url'],
                    'host' => $target['host'],
                ]);
            }

            return $batch;
        });

        foreach ($batch->targets as $target) {
            ProcessScanTarget::dispatch($target);
        }

        $redirect = redirect()->route('scans.show', $batch);

        if ($request->duplicateCount() > 0) {
            $redirect->with('status', $request->duplicateCount().' URL duplikat dibuang.');
        }

        return $redirect;
    }

    public function show(ScanBatch $scanBatch): View
    {
        $scanBatch->load('targets');

        return view('scans.show', [
            'batch' => $scanBatch,
            'running' => $scanBatch->targets->contains(fn ($target) => ! $target->status->isFinished()),
            'hasResults' => $scanBatch->targets->contains(fn ($target) => $target->status->hasResult()),
        ]);
    }

    /**
     * Progress setiap website dalam batch, dipakai halaman untuk memperbarui loading bar tanpa reload.
     */
    public function progress(ScanBatch $scanBatch): JsonResponse
    {
        $scanBatch->load('targets');

        return response()->json([
            'finished' => $scanBatch->targets->every(fn (ScanTarget $target) => $target->status->isFinished()),
            'targets' => $scanBatch->targets->map(fn (ScanTarget $target) => [
                'id' => $target->id,
                'status' => $target->status->value,
                'status_label' => $target->status->label(),
                'badge_class' => $target->status->badgeClass(),
                'bar_class' => $target->status->barClass(),
                'percent' => $target->progressPercent(),
                'step' => $target->currentStep(),
            ])->values(),
        ]);
    }

    /**
     * Risk Register gabungan semua website dalam batch, tampil seperti sheet Perangkat Lunak pada template.
     */
    public function riskRegister(ScanBatch $scanBatch): View
    {
        return view('scans.risk-register', [
            'batch' => $scanBatch,
            'items' => $scanBatch->riskItems()->get(),
        ]);
    }

    public function cancel(ScanBatch $scanBatch): RedirectResponse
    {
        $cancelled = $scanBatch->targets()
            ->where('status', ScanTargetStatus::Queued->value)
            ->update(['status' => ScanTargetStatus::Cancelled->value, 'finished_at' => now()]);

        return redirect()->route('scans.show', $scanBatch)
            ->with('status', $cancelled > 0 ? "{$cancelled} target yang masih menunggu dibatalkan." : 'Tidak ada target yang masih menunggu.');
    }

    /**
     * Risk Register gabungan semua website dalam batch.
     */
    public function export(ScanBatch $scanBatch, RiskRegisterExporter $exporter): BinaryFileResponse
    {
        return $exporter->download($scanBatch->riskItems()->get(), "Risk Register SIPRIKA - Batch {$scanBatch->id}.xlsx");
    }
}
