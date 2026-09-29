<?php

namespace Tests\Feature;

use App\Enums\ScanTargetStatus;
use App\Enums\Severity;
use App\Models\RiskRegisterItem;
use App\Models\ScanBatch;
use App\Risk\RiskEngine;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;
use Tests\Support\FakeNetwork;
use Tests\Support\InteractsWithScanner;
use Tests\TestCase;

class RecalculateCommandTest extends TestCase
{
    use InteractsWithScanner;
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        $this->setUpScanner();

        FakeNetwork::http([
            'https://web.jemberkab.go.id/' => Http::response('<title>Dinas Contoh</title>', 200, ['Server' => 'Apache/2.4.41']),
            'http://web.jemberkab.go.id/' => Http::response('<title>Dinas Contoh</title>', 200),
        ]);
    }

    public function test_menghitung_ulang_risk_register_lama_tanpa_memindai_ulang(): void
    {
        $target = $this->scan();
        $observations = $target->observations()->count();
        $findings = $target->findings()->pluck('id')->all();
        $requests = count(Http::recorded());

        // Baris lama sebelum kolom residual ada
        RiskRegisterItem::query()->update(['residual_impact' => null, 'residual_likelihood' => null, 'residual_risk' => null, 'residual_status' => null]);
        $this->assertFalse($target->riskItems()->first()->hasResidual());

        $this->artisan('siprika:recalculate', ['batch' => $target->scan_batch_id])
            ->expectsOutputToContain("Batch #{$target->scan_batch_id}")
            ->assertSuccessful();

        $items = $target->riskItems()->get();
        $this->assertNotEmpty($items);

        foreach ($items as $item) {
            $this->assertTrue($item->hasResidual(), $item->finding_key);
            $this->assertSame($item->impact, $item->residual_impact);
            $this->assertSame(1, $item->residual_likelihood);
        }

        // Tidak ada permintaan HTTP baru, observation dan finding tetap
        $this->assertCount($requests, Http::recorded());
        $this->assertSame($observations, $target->observations()->count());
        $this->assertSame($findings, $target->findings()->pluck('id')->all());
    }

    public function test_aturan_residual_dari_config_dipakai_saat_hitung_ulang(): void
    {
        $target = $this->scan();

        config(['siprika_risk.residual.likelihood' => 2]);
        $this->artisan('siprika:recalculate', ['batch' => $target->scan_batch_id])->assertSuccessful();

        $item = $target->riskItems()->first();

        $this->assertSame(2, $item->residual_likelihood);
        $this->assertSame(config('siprika_risk.matrix')[2][$item->impact], $item->residual_risk);
        $this->assertSame($item->residual_risk >= 11 ? 'Not Acceptable' : 'Acceptable', $item->residual_status);
    }

    public function test_opsi_all_menghitung_semua_batch_dan_melewati_website_tanpa_hasil(): void
    {
        $first = $this->scan();
        $second = $this->scan();
        $failed = $second->batch->targets()->create(['position' => 2, 'url' => 'https://gagal.jemberkab.go.id', 'host' => 'gagal.jemberkab.go.id', 'status' => ScanTargetStatus::Failed]);
        RiskRegisterItem::query()->update(['residual_impact' => null, 'residual_likelihood' => null]);

        $this->artisan('siprika:recalculate', ['--all' => true])
            ->expectsOutputToContain("Batch #{$first->scan_batch_id}")
            ->expectsOutputToContain("Batch #{$second->scan_batch_id}")
            ->assertSuccessful();

        $this->assertSame(0, RiskRegisterItem::whereNull('residual_impact')->count());
        $this->assertSame(0, $failed->riskItems()->count());
    }

    public function test_tanpa_batch_atau_batch_tidak_ada_ditolak(): void
    {
        $this->artisan('siprika:recalculate')
            ->expectsOutputToContain('--all')
            ->assertExitCode(2);

        $this->artisan('siprika:recalculate', ['batch' => 999])
            ->expectsOutputToContain('Batch 999 tidak ditemukan')
            ->assertFailed();

        $this->assertSame(0, ScanBatch::count());
    }

    public function test_hitung_ulang_membuang_cipher_tls_biasa_dari_nuclei_yang_dulu_dianggap_lemah(): void
    {
        $target = $this->scan();
        $nucleiRaw = fn (string $cipher) => ['template' => 'weak-cipher-suites:tls-1.1', 'extracted' => ["[tls11 {$cipher}]"]];

        // Hasil lama: AES-CBC di TLS 1.1 dari Nuclei tercatat sebagai cipher lemah
        $old = $target->findings()->create(['finding_key' => 'tls-weak-cipher', 'title' => 'Cipher TLS lemah masih diterima', 'severity' => Severity::Medium, 'sources' => ['nuclei']]);
        $old->evidences()->create(['source' => 'nuclei', 'detail' => 'template Nuclei weak-cipher-suites:tls-1.1 cocok', 'endpoint' => 'web.jemberkab.go.id:443', 'raw' => $nucleiRaw('TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA')]);

        // Website lain: testssl.sh menemukan 3DES sungguhan, bukti Nuclei AES-CBC-nya ikut tersimpan
        $other = $target->batch->targets()->create(['position' => 2, 'url' => 'https://lain.jemberkab.go.id', 'host' => 'lain.jemberkab.go.id', 'status' => ScanTargetStatus::Completed]);
        $mixed = $other->findings()->create(['finding_key' => 'tls-weak-cipher', 'title' => 'Cipher TLS lemah masih diterima', 'severity' => Severity::Medium, 'sources' => ['testssl', 'nuclei']]);
        $mixed->evidences()->create(['source' => 'testssl', 'detail' => 'server menerima cipher lemah kategori 3DES_IDEA (testssl.sh)', 'endpoint' => 'https://lain.jemberkab.go.id/']);
        $mixed->evidences()->create(['source' => 'nuclei', 'detail' => 'template Nuclei weak-cipher-suites:tls-1.1 cocok', 'endpoint' => 'lain.jemberkab.go.id:443', 'raw' => $nucleiRaw('TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA')]);

        foreach ([$target, $other] as $website) {
            app(RiskEngine::class)->assess($website);
            $this->assertTrue($website->riskItems()->where('finding_key', 'tls-weak-cipher')->exists());
        }

        $this->artisan('siprika:recalculate', ['batch' => $target->scan_batch_id])
            ->expectsOutputToContain('Bukti Nuclei dibuang')
            ->assertSuccessful();

        $this->assertFalse($target->findings()->where('finding_key', 'tls-weak-cipher')->exists());
        $this->assertFalse($target->riskItems()->where('finding_key', 'tls-weak-cipher')->exists());

        $mixed->refresh();
        $this->assertSame(['testssl'], $mixed->sources);
        $this->assertSame(['testssl'], $mixed->evidences()->pluck('source')->all());
        $this->assertTrue($other->riskItems()->where('finding_key', 'tls-weak-cipher')->exists());

        // Hitung ulang kedua kali tidak mengubah apa pun lagi
        $this->artisan('siprika:recalculate', ['batch' => $target->scan_batch_id])
            ->doesntExpectOutputToContain('Bukti Nuclei dibuang')
            ->assertSuccessful();
    }
}
