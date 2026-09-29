<?php

namespace Tests\Feature;

use App\Enums\ObservationStatus;
use App\Enums\ScanMode;
use App\Enums\ScanTargetStatus;
use App\Enums\Severity;
use App\Models\ScanBatch;
use App\Models\ScanTarget;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

/**
 * Tampilan halaman beranda dan hasil pemeriksaan.
 */
class ResultPagesTest extends TestCase
{
    use RefreshDatabase;

    private function target(ScanTargetStatus $status = ScanTargetStatus::Completed, string $host = 'web.jemberkab.go.id', ?ScanBatch $batch = null): ScanTarget
    {
        $batch ??= ScanBatch::create(['mode' => ScanMode::Standard]);

        return $batch->targets()->create([
            'position' => $batch->targets()->count() + 1,
            'url' => "https://{$host}",
            'host' => $host,
            'status' => $status,
        ]);
    }

    public function test_beranda_menampilkan_website_dan_status_pemeriksaan_terakhir(): void
    {
        $first = $this->target();
        $this->target(ScanTargetStatus::Failed, 'gagal.jemberkab.go.id', $first->batch);
        $this->target(ScanTargetStatus::Completed, 'lain.jemberkab.go.id', $first->batch);

        $this->get(route('scans.create'))
            ->assertOk()
            ->assertSee('web.jemberkab.go.id, gagal.jemberkab.go.id')
            ->assertSee('dan 1 lainnya')
            ->assertSee('2 Selesai')
            ->assertSee('1 Gagal')
            // Contoh input memakai domain yang ada di DNS
            ->assertSee('e-sakip.jemberkab.go.id')
            ->assertDontSee('esakip.jemberkab.go.id');
    }

    public function test_sumber_temuan_ditampilkan_dengan_nama_yang_mudah_dibaca(): void
    {
        $target = $this->target();
        $finding = $target->findings()->create([
            'finding_key' => 'missing-hsts',
            'title' => 'Header Strict-Transport-Security tidak diterapkan',
            'severity' => Severity::Low,
            'sources' => ['internal', 'zap'],
        ]);
        $finding->evidences()->create(['source' => 'zap', 'detail' => 'Strict-Transport-Security Header Not Set (OWASP ZAP)', 'endpoint' => 'https://web.jemberkab.go.id']);
        $target->observations()->create(['check_key' => 'header-hsts', 'label' => 'HSTS', 'tool' => 'internal', 'status' => ObservationStatus::Fail, 'summary' => 'Header tidak ditemukan.']);

        $this->get(route('targets.show', ['scanTarget' => $target, 'tab' => 'findings']))
            ->assertOk()
            ->assertSee('Pemeriksaan bawaan, OWASP ZAP')
            ->assertSee('[OWASP ZAP]')
            ->assertDontSee('[zap]');

        $this->get(route('targets.show', ['scanTarget' => $target, 'tab' => 'coverage']))
            ->assertOk()
            ->assertSee('Ditemukan oleh: Pemeriksaan bawaan, OWASP ZAP.');
    }

    public function test_informasi_nuclei_dikelompokkan_terpisah_dari_kerawanan(): void
    {
        $target = $this->target();
        $target->findings()->create(['finding_key' => 'missing-referrer-policy', 'title' => 'Referrer-Policy tidak diterapkan', 'severity' => Severity::Info, 'sources' => ['internal']]);
        $target->findings()->create(['finding_key' => 'nuclei:ssl-issuer', 'title' => 'Detect SSL Certificate Issuer', 'severity' => Severity::Info, 'sources' => ['nuclei']]);
        $target->findings()->create(['finding_key' => 'nuclei:CVE-2023-1234', 'title' => 'Contoh CVE', 'severity' => Severity::High, 'sources' => ['nuclei']]);

        $page = $this->get(route('targets.show', ['scanTarget' => $target, 'tab' => 'findings']))->assertOk();

        // Kunci katalog berseverity info tetap kerawanan; hanya hasil Nuclei info di luar katalog yang dipisah
        $page->assertSeeInOrder(['Contoh CVE', 'Referrer-Policy tidak diterapkan', 'Informasi dari scanner (1)', 'Detect SSL Certificate Issuer']);
        // Jumlah di tab hanya menghitung kerawanan
        $this->assertMatchesRegularExpression('/Findings\s*(<!--.*?-->\s*)?<span data-tab-count[^>]*>2<\/span>/s', $page->getContent());
    }

    public function test_overview_menampilkan_sertifikat_kedaluwarsa_dan_waktu_lintas_hari(): void
    {
        $target = $this->target();
        $target->update([
            'overview' => ['tls' => ['protocol' => 'TLSv1.2', 'issuer' => 'R11', 'valid_to' => '2026-09-20', 'days_left' => -3]],
            'started_at' => '2026-09-27 23:50:00',
            'finished_at' => '2026-09-28 00:20:00',
        ]);

        $this->get(route('targets.show', $target))
            ->assertOk()
            ->assertSee('kedaluwarsa 3 hari lalu')
            ->assertSee('27-09-2026 23:50:00 s.d. 28-09-2026 00:20:00');
    }

    public function test_tab_security_check_menampilkan_owasp_zap(): void
    {
        $target = $this->target();
        $target->observations()->create(['check_key' => 'zap-passive', 'label' => 'OWASP ZAP Passive', 'tool' => 'zap', 'status' => ObservationStatus::Info, 'summary' => '3 alert: Re-examine Cache-control Directives.']);

        $this->get(route('targets.show', ['scanTarget' => $target, 'tab' => 'security']))
            ->assertOk()
            ->assertSee('OWASP ZAP Passive')
            ->assertSee('Re-examine Cache-control Directives');
    }
}
