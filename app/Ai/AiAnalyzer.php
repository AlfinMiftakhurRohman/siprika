<?php

namespace App\Ai;

use App\Models\AiAnalysis;
use App\Models\ScanFinding;
use App\Models\ScanTarget;
use App\Risk\RiskEngine;
use Illuminate\Http\Client\ConnectionException;
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

        $findings = $target->findings()->get()
            ->filter(fn (ScanFinding $finding) => $this->riskEngine->rule($finding) !== null)
            ->unique('finding_key');

        $analyzed = [];
        $reused = [];
        $rejected = [];

        foreach ($findings as $finding) {
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
                    'raw' => ['analyzed' => $analyzed, 'reused' => $reused, 'rejected' => $rejected, 'error' => $e->getMessage()],
                ];
            } catch (RuntimeException $e) {
                $rejected[$finding->finding_key] = $e->getMessage();

                continue;
            }

            $reason = $this->validator->reject($output, $input);

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

        return [
            'status' => $rejected === [] ? 'done' : 'partial',
            'summary' => $summary,
            'raw' => ['analyzed' => $analyzed, 'reused' => $reused, 'rejected' => $rejected],
        ];
    }

    /**
     * JSON finding hasil normalizer, tanpa URL atau output mentah scanner (bagian 27).
     *
     * Hasil AI disimpan per kunci finding dan dipakai ulang untuk website lain, jadi input hanya berisi
     * informasi jenis finding (katalog atau template Nuclei), bukan evidence website tertentu seperti
     * nama host, cookie, atau versi. Detail per website tetap masuk kolom Kerawanan lewat RiskEngine.
     *
     * @return array<string, mixed>
     */
    public function input(ScanFinding $finding): array
    {
        $rule = $this->riskEngine->rule($finding) ?? [];
        $stripUrls = fn (?string $text) => $text === null ? null : trim(preg_replace('/\b(?:https?:\/\/|www\.)[^\s"\'<>]+/i', '[url]', $text));

        return array_filter([
            'finding_key' => $finding->finding_key,
            'title' => $finding->title,
            'description' => $stripUrls($finding->description),
            'severity' => $finding->severity->value,
            'cve' => $finding->cve,
            'cvss' => $finding->cvss,
            'category' => $rule['category'] ?? null,
            'threat' => $rule['threat'] ?? null,
            'vulnerability' => $rule['vulnerability'] ?? null,
        ], fn ($value) => $value !== null && $value !== []);
    }
}
