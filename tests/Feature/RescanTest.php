<?php

namespace Tests\Feature;

use App\Enums\ScanMode;
use App\Enums\ScanTargetStatus;
use App\Jobs\ProcessScanTarget;
use App\Models\ScanBatch;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Queue;
use Tests\TestCase;

/**
 * Pindai ulang batch atau satu website dengan mode yang sama, tanpa menghapus hasil lama.
 */
class RescanTest extends TestCase
{
    use RefreshDatabase;

    private function finishedBatch(ScanMode $mode = ScanMode::Quick): ScanBatch
    {
        $batch = ScanBatch::create(['mode' => $mode]);

        foreach (['https://a.jemberkab.go.id', 'https://b.jemberkab.go.id'] as $index => $url) {
            $batch->targets()->create([
                'position' => $index + 1,
                'url' => $url,
                'host' => parse_url($url, PHP_URL_HOST),
                'status' => ScanTargetStatus::Completed,
            ]);
        }

        return $batch;
    }

    public function test_pindai_ulang_batch_membuat_batch_baru_dengan_url_dan_mode_yang_sama(): void
    {
        Queue::fake();
        $old = $this->finishedBatch();

        $response = $this->post(route('scans.rescan', $old));

        $new = ScanBatch::latest('id')->first();
        $this->assertNotSame($old->id, $new->id);
        $response->assertRedirect(route('scans.show', $new))->assertSessionHas('status');

        $this->assertSame(ScanMode::Quick, $new->mode);
        $this->assertSame(['https://a.jemberkab.go.id', 'https://b.jemberkab.go.id'], $new->targets->pluck('url')->all());
        $this->assertSame([1, 2], $new->targets->pluck('position')->all());
        $this->assertTrue($new->targets->every(fn ($target) => $target->status === ScanTargetStatus::Queued));
        Queue::assertPushed(ProcessScanTarget::class, 2);

        // Hasil lama tetap tersimpan
        $this->assertSame(2, $old->targets()->where('status', ScanTargetStatus::Completed->value)->count());
    }

    public function test_pindai_ulang_satu_website(): void
    {
        Queue::fake();
        $old = $this->finishedBatch(ScanMode::Standard);
        $target = $old->targets()->where('position', 2)->first();

        $this->post(route('targets.rescan', $target))->assertRedirect();

        $new = ScanBatch::latest('id')->first();
        $this->assertSame(ScanMode::Standard, $new->mode);
        $this->assertSame(['https://b.jemberkab.go.id'], $new->targets->pluck('url')->all());
        Queue::assertPushed(ProcessScanTarget::class, 1);
    }

    public function test_tombol_pindai_ulang_hanya_tampil_setelah_pemeriksaan_selesai(): void
    {
        $batch = $this->finishedBatch();
        $target = $batch->targets->first();

        $this->get(route('scans.show', $batch))->assertSee(route('scans.rescan', $batch));
        $this->get(route('targets.show', $target))->assertSee(route('targets.rescan', $target));

        $target->update(['status' => ScanTargetStatus::Running]);

        $this->get(route('scans.show', $batch))->assertDontSee(route('scans.rescan', $batch));
        $this->get(route('targets.show', $target))->assertDontSee(route('targets.rescan', $target));
    }

    public function test_pindai_ulang_ditolak_selama_masih_ada_website_yang_diperiksa(): void
    {
        Queue::fake();
        $batch = $this->finishedBatch();
        $running = $batch->targets->last();
        $running->update(['status' => ScanTargetStatus::Running]);

        // Permintaan lama atau klik ganda dari halaman sebelum tombol disembunyikan
        $this->post(route('scans.rescan', $batch))
            ->assertRedirect(route('scans.show', $batch))
            ->assertSessionHas('status', fn (string $status) => str_contains($status, 'masih berjalan'));

        $this->post(route('targets.rescan', $running))
            ->assertRedirect(route('targets.show', $running))
            ->assertSessionHas('status', fn (string $status) => str_contains($status, 'sedang diperiksa'));

        $this->assertSame(1, ScanBatch::count());
        Queue::assertNothingPushed();

        // Website lain yang sudah selesai tetap dapat dipindai ulang
        $this->post(route('targets.rescan', $batch->targets->first()))->assertRedirect();
        $this->assertSame(2, ScanBatch::count());
    }
}
