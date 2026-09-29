<?php

namespace Tests\Feature;

use App\Enums\ScanMode;
use App\Enums\ScanTargetStatus;
use App\Jobs\ProcessScanTarget;
use App\Models\ScanBatch;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Tests\Support\FakeNetwork;
use Tests\Support\InteractsWithScanner;
use Tests\TestCase;

/**
 * Halaman Riwayat: memilih beberapa atau semua riwayat, lalu menghapusnya beserta seluruh hasil pemeriksaan.
 */
class HistoryCleanupTest extends TestCase
{
    use InteractsWithScanner;
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        $this->setUpScanner();
    }

    /**
     * Batch selesai dengan hasil pemeriksaan lengkap: observasi, temuan, bukti, dan Risk Register.
     */
    private function scannedBatch(string $host): ScanBatch
    {
        FakeNetwork::http([
            "https://{$host}/" => Http::response('<html><head><title>Dinas Contoh</title></head></html>', 200, ['Server' => 'Apache/2.4.41']),
            "http://{$host}/" => Http::response('<title>Dinas Contoh</title>', 200),
            "https://{$host}/.env" => Http::response("APP_KEY=base64:rahasia\n", 200),
        ]);

        return $this->scan("https://{$host}", mode: ScanMode::Quick)->batch;
    }

    private function batchWithStatus(ScanTargetStatus $status): ScanBatch
    {
        $batch = ScanBatch::create(['mode' => ScanMode::Quick]);
        $batch->targets()->create(['position' => 1, 'url' => 'https://web.jemberkab.go.id', 'host' => 'web.jemberkab.go.id', 'status' => $status]);

        return $batch;
    }

    /**
     * Jumlah baris hasil pemeriksaan milik batch di setiap tabel.
     *
     * @return array<string, int>
     */
    private function results(ScanBatch $batch): array
    {
        $targets = DB::table('scan_targets')->where('scan_batch_id', $batch->id)->pluck('id');
        $findings = DB::table('scan_findings')->whereIn('scan_target_id', $targets)->pluck('id');

        return [
            'scan_targets' => $targets->count(),
            'scan_observations' => DB::table('scan_observations')->whereIn('scan_target_id', $targets)->count(),
            'scan_findings' => $findings->count(),
            'finding_evidences' => DB::table('finding_evidences')->whereIn('scan_finding_id', $findings)->count(),
            'risk_register_items' => DB::table('risk_register_items')->whereIn('scan_target_id', $targets)->count(),
        ];
    }

    public function test_hapus_beberapa_riwayat_beserta_seluruh_hasilnya(): void
    {
        $first = $this->scannedBatch('satu.jemberkab.go.id');
        $second = $this->scannedBatch('dua.jemberkab.go.id');
        $kept = $this->scannedBatch('tiga.jemberkab.go.id');
        $keptResults = $this->results($kept);
        $this->assertGreaterThan(0, $keptResults['finding_evidences']);
        $this->assertGreaterThan(0, $keptResults['risk_register_items']);

        $this->delete(route('scans.destroy'), ['batches' => [$first->id, $second->id]])
            ->assertRedirect(route('scans.index'))
            ->assertSessionHas('status', '2 riwayat pemeriksaan dihapus beserta hasilnya.');

        $this->assertSame([$kept->id], ScanBatch::pluck('id')->all());
        $this->assertSame(array_fill_keys(array_keys($keptResults), 0), $this->results($first));
        $this->assertSame($keptResults, $this->results($kept));

        // Tidak ada baris yatim di tabel mana pun
        foreach ($keptResults as $table => $count) {
            $this->assertSame($count, DB::table($table)->count(), $table);
        }
    }

    public function test_batch_yang_masih_berjalan_tidak_dapat_dipilih_dan_tidak_dihapus(): void
    {
        $running = $this->batchWithStatus(ScanTargetStatus::Running);
        $queued = $this->batchWithStatus(ScanTargetStatus::Queued);
        $finished = $this->batchWithStatus(ScanTargetStatus::Completed);

        $page = $this->get(route('scans.index'))->assertOk()->getContent();
        $this->assertStringContainsString('name="batches[]" value="'.$finished->id.'"', $page);
        $this->assertStringNotContainsString('name="batches[]" value="'.$running->id.'"', $page);
        $this->assertStringNotContainsString('name="batches[]" value="'.$queued->id.'"', $page);

        // Permintaan langsung tetap tidak menghapus batch yang berjalan
        $this->delete(route('scans.destroy'), ['batches' => [$running->id, $queued->id, $finished->id]])
            ->assertSessionHas('status', '1 riwayat pemeriksaan dihapus beserta hasilnya. 2 batch masih berjalan sehingga tidak dihapus.');

        $this->assertEqualsCanonicalizing([$running->id, $queued->id], ScanBatch::pluck('id')->all());
    }

    public function test_riwayat_ditampilkan_per_halaman_dan_semua_riwayat_dapat_dihapus_sekaligus(): void
    {
        foreach (range(1, 30) as $index) {
            $this->batchWithStatus($index % 2 === 0 ? ScanTargetStatus::Completed : ScanTargetStatus::Failed);
        }
        $running = $this->batchWithStatus(ScanTargetStatus::Running);

        $first = $this->get(route('scans.index'))->assertOk()->assertSee('Halaman 1 dari 2')->assertSee('Pilih semua 30 riwayat');
        $this->assertSame(24, substr_count($first->getContent(), 'data-bulk-item'), '25 batch per halaman, satu masih berjalan');
        $this->assertSame(6, substr_count($this->get(route('scans.index', ['page' => 2]))->getContent(), 'data-bulk-item'));

        $this->delete(route('scans.destroy'), ['all' => '1'])
            ->assertSessionHas('status', '30 riwayat pemeriksaan dihapus beserta hasilnya. 1 batch masih berjalan sehingga tidak dihapus.');

        $this->assertSame([$running->id], ScanBatch::pluck('id')->all());
    }

    public function test_tanpa_pilihan_atau_pilihan_tidak_valid_ditolak(): void
    {
        $batch = $this->batchWithStatus(ScanTargetStatus::Completed);

        $this->from(route('scans.index'))->delete(route('scans.destroy'), ['all' => '0'])
            ->assertRedirect(route('scans.index'))
            ->assertSessionHasErrors(['batches' => 'Pilih minimal satu riwayat yang akan dihapus.']);

        $this->from(route('scans.index'))->delete(route('scans.destroy'), ['batches' => ['abc']])
            ->assertSessionHasErrors(['batches.0' => 'Pilihan riwayat tidak valid.']);

        $this->delete(route('scans.destroy'), ['batches' => [999]])
            ->assertSessionHas('status', 'Tidak ada riwayat yang dihapus.');

        $this->assertSame([$batch->id], ScanBatch::pluck('id')->all());

        // Pesan error tampil di halaman Riwayat
        $this->from(route('scans.index'))->followingRedirects()->delete(route('scans.destroy'))
            ->assertOk()
            ->assertSee('Pilih minimal satu riwayat yang akan dihapus.');
    }

    public function test_job_antrean_website_yang_riwayatnya_dihapus_dilewati_tanpa_dicatat_gagal(): void
    {
        config(['queue.default' => 'database']);
        $batch = $this->batchWithStatus(ScanTargetStatus::Queued);
        ProcessScanTarget::dispatch($batch->targets->first());

        // Website dibatalkan saat masih di antrean, lalu riwayatnya dihapus sebelum worker mengambil job-nya
        $batch->targets()->update(['status' => ScanTargetStatus::Cancelled->value]);
        $this->delete(route('scans.destroy'), ['batches' => [$batch->id]])->assertSessionHas('status', '1 riwayat pemeriksaan dihapus beserta hasilnya.');
        $this->assertSame(1, DB::table('jobs')->count());

        $this->artisan('queue:work', ['--once' => true, '--stop-when-empty' => true])->assertSuccessful();

        $this->assertSame(0, DB::table('jobs')->count());
        $this->assertSame(0, DB::table('failed_jobs')->count());
    }

    public function test_riwayat_dapat_dibuka_dari_navigasi_beranda_dan_halaman_batch(): void
    {
        $batch = $this->batchWithStatus(ScanTargetStatus::Completed);

        $this->get(route('scans.create'))
            ->assertOk()
            ->assertSee('href="'.route('scans.index').'"', false)
            ->assertSee('Lihat semua &amp; hapus riwayat', false);

        $this->get(route('scans.show', $batch))->assertOk()->assertSee('href="'.route('scans.index').'"', false);
    }

    public function test_riwayat_kosong(): void
    {
        $this->get(route('scans.index'))
            ->assertOk()
            ->assertSee('Belum ada riwayat pemeriksaan.')
            ->assertDontSee('data-bulk-form', false);
    }
}
