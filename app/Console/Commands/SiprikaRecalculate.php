<?php

namespace App\Console\Commands;

use App\Ai\AiAnalyzer;
use App\Models\FindingEvidence;
use App\Models\ScanBatch;
use App\Models\ScanTarget;
use App\Risk\RiskEngine;
use App\Scanner\Parsers\NucleiParser;
use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;

#[Signature('siprika:recalculate {batch? : ID batch yang dihitung ulang} {--all : Hitung ulang semua batch}')]
#[Description('Menghitung ulang Risk Register dari finding yang sudah tersimpan, tanpa memindai ulang website dan tanpa memanggil AI')]
class SiprikaRecalculate extends Command
{
    public function handle(RiskEngine $engine, AiAnalyzer $analyzer): int
    {
        $batchId = $this->argument('batch');

        if ($batchId === null && ! $this->option('all')) {
            $this->components->error('Sebutkan ID batch, contoh: php artisan siprika:recalculate 3, atau pakai --all.');

            return self::INVALID;
        }

        $batches = $batchId !== null
            ? ScanBatch::whereKey($batchId)->get()
            : ScanBatch::orderBy('id')->get();

        if ($batches->isEmpty()) {
            $this->components->error("Batch {$batchId} tidak ditemukan.");

            return self::FAILURE;
        }

        $purged = [];
        $dropped = 0;

        foreach ($batches as $batch) {
            // Hanya website yang pemeriksaannya selesai (COMPLETED atau PARTIAL) yang punya Risk Register
            $targets = $batch->targets()->get()->filter(fn ($target) => $target->status->hasResult());

            foreach ($targets as $target) {
                $dropped += $this->dropOutdatedNucleiEvidence($target);

                // Hasil AI tersimpan dicek ulang terhadap evidence website ini (bagian 27), yang gagal dihapus
                $purged += $analyzer->purgeInvalid($target);
                $engine->assess($target);
            }

            $this->components->twoColumnDetail(
                "Batch #{$batch->id}",
                "{$targets->count()} website, {$batch->riskItems()->count()} baris Risk Register",
            );
        }

        if ($dropped > 0) {
            $this->components->twoColumnDetail('Bukti Nuclei dibuang', "{$dropped} bukti tidak sesuai aturan terbaru (contoh cipher TLS biasa bukan cipher lemah, deteksi WAF/S3 heuristik)");
        }

        foreach ($purged as $key => $reason) {
            $this->components->twoColumnDetail("Hasil AI {$key} dihapus", $reason);
        }

        $this->components->info('Risk Register selesai dihitung ulang.');

        return self::SUCCESS;
    }

    /**
     * Bukti Nuclei yang tidak lagi lolos aturan parser terbaru dibuang. Finding tanpa bukti tersisa ikut dihapus,
     * beserta baris Risk Register-nya (foreign key cascade).
     */
    private function dropOutdatedNucleiEvidence(ScanTarget $target): int
    {
        $dropped = 0;

        foreach ($target->findings()->with('evidences')->get() as $finding) {
            $outdated = $finding->evidences->filter(fn (FindingEvidence $evidence) => $evidence->source === 'nuclei'
                && ! NucleiParser::acceptsStoredEvidence($finding->finding_key, (array) $evidence->raw));

            if ($outdated->isEmpty()) {
                continue;
            }

            $dropped += $outdated->count();

            if ($outdated->count() === $finding->evidences->count()) {
                $finding->delete();

                continue;
            }

            $outdated->each->delete();
            $finding->update(['sources' => array_values(array_diff($finding->sources, ['nuclei']))]);
        }

        return $dropped;
    }
}
