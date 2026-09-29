<?php

namespace App\Http\Controllers;

use App\Enums\ScanMode;
use App\Enums\ScanTargetStatus;
use App\Http\Requests\StoreScanRequest;
use App\Models\RiskRegisterItem;
use App\Models\ScanBatch;
use App\Models\ScanTarget;
use App\Report\RawReportExporter;
use App\Risk\RiskRegisterExporter;
use App\Scanner\ScanQueue;
use App\Support\TargetUrlNormalizer;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\View\View;
use Symfony\Component\HttpFoundation\BinaryFileResponse;

class ScanController extends Controller
{
    private const HISTORY_PER_PAGE = 25;

    /**
     * Semua riwayat pemeriksaan, terbaru di atas, untuk dibuka atau dibersihkan.
     */
    public function index(): View
    {
        return view('scans.index', [
            'batches' => ScanBatch::with('targets')->latest('id')->paginate(self::HISTORY_PER_PAGE),
            // Jumlah untuk pilihan "semua riwayat"; batch yang masih berjalan tidak ikut dihapus
            'deletableCount' => ScanBatch::finished()->count(),
        ]);
    }

    /**
     * Menghapus riwayat yang dipilih atau semua riwayat, beserta website, temuan, dan Risk Register-nya
     * (foreign key cascade). Batch yang masih berjalan dilewati supaya pemeriksaan yang sedang berjalan tidak rusak.
     */
    public function destroy(Request $request): RedirectResponse
    {
        $request->validate([
            'all' => ['nullable', 'boolean'],
            'batches' => ['required_unless:all,1', 'array'],
            'batches.*' => ['integer'],
        ], [
            'batches.required_unless' => 'Pilih minimal satu riwayat yang akan dihapus.',
            'batches.array' => 'Pilihan riwayat tidak valid.',
            'batches.*.integer' => 'Pilihan riwayat tidak valid.',
        ]);

        $selected = ScanBatch::query()->unless($request->boolean('all'), fn (Builder $query) => $query->whereKey($request->input('batches')));
        $total = $selected->count();
        $deleted = $selected->finished()->delete();
        $running = $total - $deleted;

        $message = $deleted > 0 ? "{$deleted} riwayat pemeriksaan dihapus beserta hasilnya." : 'Tidak ada riwayat yang dihapus.';

        if ($running > 0) {
            $message .= " {$running} batch masih berjalan sehingga tidak dihapus.";
        }

        return redirect()->route('scans.index')->with('status', $message);
    }

    public function create(): View
    {
        return view('scans.create', [
            'modes' => ScanMode::cases(),
            'defaultMode' => ScanMode::Standard,
            'allowsAllDomains' => TargetUrlNormalizer::fromConfig()->allowsAllDomains(),
            'recentBatches' => ScanBatch::with('targets')->latest('id')->limit(10)->get(),
        ]);
    }

    public function store(StoreScanRequest $request, ScanQueue $queue): RedirectResponse
    {
        // Urutan antrean mengikuti urutan baris input
        $batch = $queue->start($request->mode(), $request->targets());

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
            'running' => $scanBatch->isRunning(),
            'hasResults' => $scanBatch->targets->contains(fn ($target) => $target->status->hasResult()),
            'riskCount' => $scanBatch->riskItems()->count(),
            'notAcceptableCount' => $scanBatch->riskItems()->where('risk_status', RiskRegisterItem::NOT_ACCEPTABLE)->count(),
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
                'elapsed' => $target->elapsedSeconds(),
                'remaining' => $target->remainingSeconds(),
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

    /**
     * Pindai ulang semua website dalam batch dengan mode yang sama, contoh setelah aturan pemeriksaan diperbarui.
     */
    public function rescan(ScanBatch $scanBatch, ScanQueue $queue): RedirectResponse
    {
        // Tombol hanya tampil setelah selesai; permintaan ganda atau lama tidak membuat pemeriksaan ganda
        if ($scanBatch->isRunning()) {
            return redirect()->route('scans.show', $scanBatch)
                ->with('status', "Batch #{$scanBatch->id} masih berjalan. Pindai ulang dapat dilakukan setelah semua website selesai diperiksa.");
        }

        $batch = $queue->restart($scanBatch->mode, $scanBatch->targets);

        return redirect()->route('scans.show', $batch)
            ->with('status', "Pemindaian ulang Batch #{$scanBatch->id}. Hasil lama tetap tersimpan di batch tersebut.");
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

    /**
     * Laporan mentah semua website dalam batch: semua pemeriksaan, temuan, teknologi, dan hasil tool (bukan template).
     */
    public function rawReport(ScanBatch $scanBatch, RawReportExporter $exporter): BinaryFileResponse
    {
        return $exporter->download($scanBatch->targets()->get(), "Laporan Mentah SIPRIKA - Batch {$scanBatch->id}.xlsx");
    }
}
