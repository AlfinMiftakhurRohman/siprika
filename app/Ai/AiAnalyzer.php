<?php

namespace App\Ai;

use App\Models\AiAnalysis;
use App\Models\ScanFinding;
use App\Models\ScanTarget;
use App\Risk\RiskEngine;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Log;
use RuntimeException;

/**
 * Meminta analisis AI untuk finding yang menjadi baris Risk Register.
 * Hasil disimpan per kunci finding dan dipakai ulang. Kegagalan AI tidak menggagalkan scan.
 */
class AiAnalyzer
{
    public function __construct(
        private LlamaClient $client,
        private AiOutputValidator $validator,
        private RiskEngine $riskEngine,
    ) {}

    /**
     * @return array{status: string, summary: string, raw: array<string, mixed>}
     *                                                                           status: disabled, done, partial, error
     */
    public function analyze(ScanTarget $target): array
    {
        if (! config('siprika.ai.enabled')) {
            return ['status' => 'disabled', 'summary' => 'AI tidak aktif (AI_ENABLED=false), kolom deskriptif memakai teks katalog.', 'raw' => []];
        }

        $analyzed = [];
        $reused = [];
        $rejected = [];
        // Hasil tersimpan yang tidak lolos validasi terhadap website ini dihapus lalu dianalisis ulang
        $purged = $this->purgeInvalid($target);

        foreach ($this->riskFindings($target) as $finding) {
            if (AiAnalysis::where('finding_key', $finding->finding_key)->exists()) {
                $reused[] = $finding->finding_key;

                continue;
            }

            $input = $this->input($finding);

            try {
                $output = $this->client->analyze($input);
            } catch (ConnectionException $e) {
                // Layanan AI mati atau timeout: hentikan, sisanya memakai teks katalog
                Log::warning('SIPRIKA AI tidak dapat dihubungi', ['error' => $e->getMessage()]);

                return [
                    'status' => 'error',
                    'summary' => 'Layanan AI tidak dapat dihubungi atau timeout, dipakai teks katalog.',
                    'raw' => ['analyzed' => $analyzed, 'reused' => $reused, 'rejected' => $rejected, 'purged' => $purged, 'error' => $e->getMessage()],
                ];
            } catch (RuntimeException $e) {
                $rejected[$finding->finding_key] = $e->getMessage();

                continue;
            }

            $reason = $this->validator->reject($output, $input, SiteEvidence::from($finding, $target));

            if ($reason !== null) {
                $rejected[$finding->finding_key] = $reason;

                continue;
            }

            AiAnalysis::create([
                'finding_key' => $finding->finding_key,
                'finding' => $output['finding'],
                'threat' => $output['threat'],
                'vulnerability' => $output['vulnerability'],
                'category' => $output['category'],
                'impact_description' => $output['impact_description'],
                'recommendation' => $output['recommendation'],
                'additional_control' => $output['additional_control'],
                'model' => config('siprika.ai.model'),
            ]);

            $analyzed[] = $finding->finding_key;
        }

        $summary = sprintf('%d finding dianalisis AI, %d memakai hasil tersimpan, %d ditolak validasi (memakai teks katalog).', count($analyzed), count($reused), count($rejected));

        if ($purged !== []) {
            $summary .= sprintf(' %d hasil tersimpan dihapus karena tidak lolos validasi terhadap website ini.', count($purged));
        }

        return [
            'status' => $rejected === [] ? 'done' : 'partial',
            'summary' => $summary,
            'raw' => ['analyzed' => $analyzed, 'reused' => $reused, 'rejected' => $rejected, 'purged' => $purged],
        ];
    }

    /**
     * Hapus hasil AI tersimpan yang tidak lolos validasi terhadap evidence website ini, contoh memuat nama cookie
     * atau versi software website tertentu (bagian 27). Tidak memanggil AI.
     *
     * @return array<string, string> kunci finding => alasan
     */
    public function purgeInvalid(ScanTarget $target): array
    {
        $findings = $this->riskFindings($target);
        $purged = [];

        foreach (AiAnalysis::whereIn('finding_key', $findings->pluck('finding_key'))->get() as $analysis) {
            $finding = $findings->firstWhere('finding_key', $analysis->finding_key);
            $reason = $this->validator->reject($analysis->only(AiOutputValidator::KEYS), $this->input($finding), SiteEvidence::from($finding, $target));

            if ($reason !== null) {
                $analysis->delete();
                $purged[$analysis->finding_key] = $reason;
            }
        }

        return $purged;
    }

    /**
     * @return array<string, mixed>
     */
    public function input(ScanFinding $finding): array
    {
        return AiInput::build($finding, $this->riskEngine->rule($finding));
    }

    /**
     * Finding yang menjadi baris Risk Register, satu per kunci, beserta evidence-nya.
     *
     * @return Collection<int, ScanFinding>
     */
    private function riskFindings(ScanTarget $target): Collection
    {
        return $target->findings()->with('evidences')->get()
            ->filter(fn (ScanFinding $finding) => $this->riskEngine->rule($finding) !== null)
            ->unique('finding_key')
            ->values();
    }
}
