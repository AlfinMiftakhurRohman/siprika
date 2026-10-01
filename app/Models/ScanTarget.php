<?php

namespace App\Models;

use App\Enums\ScanTargetStatus;
use App\Scanner\ScanProgress;
use Database\Factories\ScanTargetFactory;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Facades\DB;

#[Fillable(['position', 'url', 'host', 'status', 'overview', 'progress', 'started_at', 'finished_at', 'error_message'])]
class ScanTarget extends Model
{
    /** @use HasFactory<ScanTargetFactory> */
    use HasFactory;

    /**
     * Nilai awal saat target baru dibuat.
     *
     * @var array<string, mixed>
     */
    protected $attributes = [
        'status' => 'QUEUED',
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'status' => ScanTargetStatus::class,
            'overview' => 'array',
            'progress' => 'array',
            'started_at' => 'datetime',
            'finished_at' => 'datetime',
        ];
    }

    /**
     * @return BelongsTo<ScanBatch, $this>
     */
    public function batch(): BelongsTo
    {
        return $this->belongsTo(ScanBatch::class, 'scan_batch_id');
    }

    /**
     * @return HasMany<ScanObservation, $this>
     */
    public function observations(): HasMany
    {
        return $this->hasMany(ScanObservation::class)->orderBy('id');
    }

    /**
     * @return HasMany<ScanFinding, $this>
     */
    public function findings(): HasMany
    {
        return $this->hasMany(ScanFinding::class);
    }

    /**
     * @return HasMany<RiskRegisterItem, $this>
     */
    public function riskItems(): HasMany
    {
        return $this->hasMany(RiskRegisterItem::class)->orderBy('priority');
    }

    /**
     * Persentase progress: 0 selama menunggu, 100 setelah selesai, selain itu dari bobot tahap (ScanProgress).
     */
    public function progressPercent(): int
    {
        return match (true) {
            $this->status === ScanTargetStatus::Queued, $this->status === ScanTargetStatus::Cancelled => 0,
            $this->status->isFinished() => 100,
            default => ScanProgress::percent($this->progress ?? []),
        };
    }

    /**
     * Lama pemeriksaan dalam detik: sampai selesai, atau sampai sekarang jika masih berjalan. Null jika belum mulai.
     */
    public function elapsedSeconds(): ?int
    {
        return $this->started_at === null ? null : (int) max(0, $this->started_at->diffInSeconds($this->finished_at ?? now()));
    }

    /**
     * Perkiraan sisa detik dari perkiraan lama setiap tahap, hanya untuk website yang sedang diperiksa.
     */
    public function remainingSeconds(): ?int
    {
        return $this->status === ScanTargetStatus::Running ? ScanProgress::remainingSeconds($this->progress ?? [], now()->getTimestampMs() / 1000) : null;
    }

    /**
     * Hapus hasil pemeriksaan dan kembalikan website ke antrean, supaya diperiksa ulang dari awal di batch yang sama.
     * Bukti temuan ikut terhapus lewat foreign key.
     */
    public function resetResults(?string $note = null): void
    {
        DB::transaction(function () use ($note) {
            $this->riskItems()->delete();
            $this->findings()->delete();
            $this->observations()->delete();

            $this->update([
                'status' => ScanTargetStatus::Queued,
                'overview' => null,
                'progress' => null,
                'started_at' => null,
                'finished_at' => null,
                'error_message' => $note,
            ]);
        });
    }

    /**
     * Label tahap yang sedang berjalan, contoh "Nuclei" atau "Nuclei + testssl.sh" saat Nuclei berjalan
     * di latar belakang, null jika tidak ada.
     */
    public function currentStep(): ?string
    {
        $running = collect($this->progress ?? [])->where('status', ScanProgress::RUNNING)->pluck('label');

        return $running->isEmpty() ? null : $running->implode(' + ');
    }

    /**
     * Nama aset untuk kolom Aset Risk Register, contoh: "Website Dinas X (dinasx.jemberkab.go.id)".
     */
    public function assetName(): string
    {
        // Title halaman blokir WAF/CDN (contoh "Just a moment...") bukan nama website
        $title = empty($this->overview['waf_blocked']) ? trim((string) ($this->overview['title'] ?? '')) : '';

        if ($title === '') {
            return "Website {$this->host}";
        }

        $title = mb_strimwidth($title, 0, 120, '...');

        return (str_starts_with(mb_strtolower($title), 'website') ? $title : "Website {$title}")." ({$this->host})";
    }
}
