<?php

namespace Tests\Feature;

use App\Enums\ScanTargetStatus;
use App\Jobs\ProcessScanTarget;
use App\Models\ScanTarget;
use App\Scanner\Network\IpGuard;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Queue\Middleware\WithoutOverlapping;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\DataProvider;
use RuntimeException;
use Tests\Support\InteractsWithScanner;
use Tests\TestCase;

class ScanJobTest extends TestCase
{
    use InteractsWithScanner;
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        $this->setUpScanner();
    }

    public function test_target_yang_dibatalkan_tidak_diperiksa(): void
    {
        Http::fake();
        $target = ScanTarget::factory()->create(['status' => ScanTargetStatus::Cancelled]);

        ProcessScanTarget::dispatchSync($target);

        $this->assertSame(ScanTargetStatus::Cancelled, $target->fresh()->status);
        $this->assertSame(0, $target->observations()->count());
        Http::assertNothingSent();
    }

    public function test_kesalahan_sistem_menandai_target_gagal(): void
    {
        $target = ScanTarget::factory()->create(['status' => ScanTargetStatus::Running]);

        (new ProcessScanTarget($target))->failed(new RuntimeException('Database terkunci'));

        $target->refresh();
        $this->assertSame(ScanTargetStatus::Failed, $target->status);
        $this->assertStringContainsString('Database terkunci', $target->error_message);
        $this->assertNotNull($target->finished_at);
    }

    public function test_hanya_satu_website_diperiksa_dalam_satu_waktu(): void
    {
        $middleware = (new ProcessScanTarget(ScanTarget::factory()->create()))->middleware();

        $this->assertCount(1, $middleware);
        $this->assertInstanceOf(WithoutOverlapping::class, $middleware[0]);
        $this->assertSame('siprika-scanner', $middleware[0]->key);
    }

    public function test_kolom_yang_bisa_melebihi_255_karakter_bertipe_text(): void
    {
        // PostgreSQL dan MySQL menolak insert yang melebihi panjang varchar
        foreach (['ai_analyses' => ['finding', 'category'], 'risk_register_items' => ['asset'], 'scan_findings' => ['title']] as $table => $columns) {
            foreach ($columns as $column) {
                $this->assertSame('text', Schema::getColumnType($table, $column), "{$table}.{$column}");
            }
        }
    }

    public function test_hasil_pemeriksaan_dicari_lewat_index_bukan_membaca_seluruh_tabel(): void
    {
        $queries = [
            'select * from scan_targets where scan_batch_id = 1',
            'select * from scan_observations where scan_target_id = 1',
            'select * from scan_findings where scan_target_id = 1',
            'select * from finding_evidences where scan_finding_id in (1, 2)',
            'select * from risk_register_items where scan_target_id = 1',
            'select * from risk_register_items where scan_finding_id = 1',
        ];

        foreach ($queries as $sql) {
            $plan = collect(DB::select("explain query plan {$sql}"))->pluck('detail')->implode('; ');

            $this->assertStringStartsWith('SEARCH', $plan, $sql);
        }
    }

    public function test_retry_after_antrean_lebih_lama_dari_batas_waktu_pemeriksaan(): void
    {
        $this->assertGreaterThan(config('siprika.scan.target_timeout'), config('queue.connections.database.retry_after'));
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function ipProvider(): array
    {
        return [
            'publik v4' => ['93.184.216.34', true],
            'publik v6' => ['2606:4700:20::681a:cdb', true],
            'privat 10' => ['10.1.2.3', false],
            'privat 172' => ['172.16.5.4', false],
            'privat 192' => ['192.168.0.1', false],
            'loopback' => ['127.0.0.1', false],
            'link-local' => ['169.254.169.254', false],
            'cgnat' => ['100.64.0.1', false],
            'dokumentasi' => ['203.0.113.10', false],
            'unspecified' => ['0.0.0.0', false],
            'multicast' => ['224.0.0.1', false],
            'loopback v6' => ['::1', false],
            'unique local v6' => ['fd00::1', false],
            'link-local v6' => ['fe80::1', false],
            'ipv4-mapped v6' => ['::ffff:127.0.0.1', false],
            'bukan ip' => ['bukan-ip', false],
        ];
    }

    #[DataProvider('ipProvider')]
    public function test_penjaga_ip_hanya_mengizinkan_ip_publik(string $ip, bool $public): void
    {
        $this->assertSame($public, IpGuard::isPublic($ip));
    }
}
