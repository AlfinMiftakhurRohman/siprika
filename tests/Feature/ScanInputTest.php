<?php

namespace Tests\Feature;

use App\Enums\ScanMode;
use App\Enums\ScanTargetStatus;
use App\Jobs\ProcessScanTarget;
use App\Models\ScanBatch;
use App\Models\ScanTarget;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Queue;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

class ScanInputTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        Queue::fake();
        config(['siprika.allowed_domains' => ['jemberkab.go.id']]);
    }

    public function test_halaman_input_menampilkan_pilihan_mode_cepat_dan_standar(): void
    {
        $this->get('/')
            ->assertOk()
            ->assertSee('Target Website')
            ->assertSee('Mode Pemeriksaan')
            ->assertSeeInOrder(['Cepat', 'Standar'])
            ->assertSee('name="mode" value="quick"', false)
            ->assertSee('MULAI PEMERIKSAAN');

        // Standar terpilih secara bawaan (bagian 2)
        $html = $this->get('/')->getContent();
        $this->assertMatchesRegularExpression('/value="standard"[^>]*checked/', $html);
        $this->assertDoesNotMatchRegularExpression('/value="quick"[^>]*checked/', $html);
    }

    public function test_pilihan_mode_dipertahankan_saat_input_ditolak(): void
    {
        $this->post('/scans', ['urls' => 'ftp://a.jemberkab.go.id', 'mode' => 'quick']);

        $html = $this->get('/')->getContent();
        $this->assertMatchesRegularExpression('/value="quick"[^>]*checked/', $html);
    }

    public function test_mode_cepat_disimpan_pada_batch(): void
    {
        $this->post('/scans', ['urls' => 'https://a.jemberkab.go.id', 'mode' => 'quick'])
            ->assertSessionHasNoErrors();

        $this->assertSame(ScanMode::Quick, ScanBatch::sole()->mode);
        $this->get(route('scans.show', ScanBatch::sole()))->assertSee('Cepat');
    }

    public function test_mode_tidak_valid_ditolak(): void
    {
        $this->post('/scans', ['urls' => 'https://a.jemberkab.go.id', 'mode' => 'agresif'])
            ->assertSessionHasErrors(['mode' => 'Mode pemeriksaan tidak valid, pilih Cepat atau Standar.']);

        $this->assertSame(0, ScanBatch::count());
        Queue::assertNothingPushed();
    }

    public function test_mode_wajib_dipilih(): void
    {
        $this->post('/scans', ['urls' => 'https://a.jemberkab.go.id'])
            ->assertSessionHasErrors(['mode' => 'Pilih mode pemeriksaan.']);

        $this->assertSame(0, ScanBatch::count());
    }

    public function test_halaman_input_menampilkan_pemeriksaan_terakhir(): void
    {
        $batch = ScanBatch::factory()->create();
        ScanTarget::factory()->for($batch, 'batch')->create();

        $this->get('/')
            ->assertOk()
            ->assertSee('Pemeriksaan Terakhir')
            ->assertSee(route('scans.show', $batch));
    }

    public function test_banyak_url_disimpan_sebagai_satu_batch_dan_masuk_antrean_berurutan(): void
    {
        $response = $this->post('/scans', [
            'mode' => 'standard',
            'urls' => "https://a.jemberkab.go.id\nhttps://b.jemberkab.go.id\nhttp://jemberkab.go.id",
        ]);

        $batch = ScanBatch::sole();
        $response->assertRedirect(route('scans.show', $batch));

        $this->assertSame(ScanMode::Standard, $batch->mode);
        $this->assertSame(
            [
                [1, 'https://a.jemberkab.go.id', 'a.jemberkab.go.id'],
                [2, 'https://b.jemberkab.go.id', 'b.jemberkab.go.id'],
                [3, 'http://jemberkab.go.id', 'jemberkab.go.id'],
            ],
            $batch->targets->map(fn (ScanTarget $t) => [$t->position, $t->url, $t->host])->all()
        );
        $batch->targets->each(fn (ScanTarget $t) => $this->assertSame(ScanTargetStatus::Queued, $t->status));

        // Satu job per target, dikirim sesuai urutan antrean
        $this->assertSame(
            $batch->targets->pluck('id')->all(),
            Queue::pushed(ProcessScanTarget::class)->map(fn (ProcessScanTarget $job) => $job->target->id)->values()->all()
        );
    }

    public function test_url_dinormalisasi_dan_baris_kosong_dibuang(): void
    {
        $this->post('/scans', [
            'mode' => 'standard',
            'urls' => "\n   HTTPS://Dinas-A.JemberKab.go.id/Path?x=1#bagian   \r\n\n\t\nhttps://b.jemberkab.go.id:443/\nhttp://c.jemberkab.go.id:8080/#top",
        ])->assertSessionHasNoErrors();

        $this->assertSame(
            [
                'https://dinas-a.jemberkab.go.id/Path?x=1',
                'https://b.jemberkab.go.id',
                'http://c.jemberkab.go.id:8080',
            ],
            ScanTarget::orderBy('position')->pluck('url')->all()
        );
    }

    public function test_url_duplikat_setelah_normalisasi_dibuang(): void
    {
        $this->post('/scans', [
            'mode' => 'standard',
            'urls' => "https://a.jemberkab.go.id\nhttps://A.jemberkab.go.id/\nhttps://a.jemberkab.go.id#x\nhttps://b.jemberkab.go.id",
        ])->assertSessionHas('status', '2 URL duplikat dibuang.');

        $this->assertSame(
            ['https://a.jemberkab.go.id', 'https://b.jemberkab.go.id'],
            ScanTarget::orderBy('position')->pluck('url')->all()
        );
        Queue::assertPushed(ProcessScanTarget::class, 2);
    }

    public function test_beberapa_domain_diizinkan_dari_config(): void
    {
        config(['siprika.allowed_domains' => ['jemberkab.go.id', 'contoh.id']]);

        $this->post('/scans', [
            'mode' => 'standard',
            'urls' => "https://a.jemberkab.go.id\nhttps://www.contoh.id",
        ])->assertSessionHasNoErrors();

        $this->assertSame(2, ScanTarget::count());
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function urlDitolakProvider(): array
    {
        return [
            'skema ftp' => ['ftp://a.jemberkab.go.id', 'skema ftp tidak diizinkan'],
            'skema javascript' => ['javascript:alert(1)', 'skema javascript tidak diizinkan'],
            'skema mailto' => ['mailto:admin@jemberkab.go.id', 'skema mailto tidak diizinkan'],
            'garis miring kurang' => ['https:/a.jemberkab.go.id', 'format URL tidak valid'],
            'localhost' => ['http://localhost', 'localhost tidak diizinkan'],
            'localhost tanpa skema' => ['localhost:8000', 'localhost tidak diizinkan'],
            'ip tanpa skema' => ['192.168.1.10', 'alamat IP tidak diizinkan'],
            'nama tanpa titik' => ['intranet', 'nama domain lengkap'],
            'terlalu panjang setelah ditambah https' => ['a.jemberkab.go.id/'.str_repeat('x', 2030), 'URL terlalu panjang'],
            'subdomain localhost' => ['http://app.localhost', 'localhost tidak diizinkan'],
            'ip privat' => ['http://192.168.1.10', 'alamat IP tidak diizinkan'],
            'ip loopback' => ['http://127.0.0.1:8000', 'alamat IP tidak diizinkan'],
            'ip publik' => ['https://8.8.8.8', 'alamat IP tidak diizinkan'],
            'ipv6' => ['http://[::1]/', 'alamat IP tidak diizinkan'],
            'domain lain' => ['https://google.com', 'domain google.com tidak termasuk domain yang diizinkan'],
            'domain tiruan di depan' => ['https://evil-jemberkab.go.id', 'tidak termasuk domain yang diizinkan'],
            'domain tiruan di belakang' => ['https://jemberkab.go.id.evil.com', 'tidak termasuk domain yang diizinkan'],
            'userinfo' => ['https://jemberkab.go.id@evil.com', 'nama pengguna atau kata sandi'],
            'spasi di tengah' => ['https://a.jemberkab.go.id/ab cd', 'tidak boleh mengandung spasi'],
            'tanpa host' => ['https://', 'format URL tidak valid'],
        ];
    }

    #[DataProvider('urlDitolakProvider')]
    public function test_url_tidak_valid_ditolak(string $url, string $alasan): void
    {
        $this->post('/scans', ['mode' => 'standard', 'urls' => $url])
            ->assertSessionHasErrors('urls');

        $this->assertStringContainsString($alasan, session('errors')->first('urls'));
        $this->assertSame(0, ScanBatch::count());
        Queue::assertNothingPushed();
    }

    public function test_pesan_error_menyebut_nomor_baris_dan_tidak_ada_yang_tersimpan(): void
    {
        $response = $this->post('/scans', [
            'mode' => 'standard',
            'urls' => "\nhttps://a.jemberkab.go.id\nftp://b.jemberkab.go.id\n\nhttps://10.0.0.1",
        ]);

        $response->assertSessionHasErrors('urls');
        $errors = session('errors')->get('urls');

        $this->assertCount(2, $errors);
        $this->assertStringStartsWith('Baris 3 (ftp://b.jemberkab.go.id): ', $errors[0]);
        $this->assertStringStartsWith('Baris 5 (https://10.0.0.1): ', $errors[1]);
        $this->assertSame(0, ScanBatch::count());
        $this->assertSame(0, ScanTarget::count());
    }

    public function test_url_tanpa_skema_dianggap_https(): void
    {
        $this->post('/scans', [
            'mode' => 'quick',
            'urls' => "esakip.jemberkab.go.id\nWeb.JemberKab.go.id/profil?id=1\ndinas.jemberkab.go.id:8080\nhttp://lama.jemberkab.go.id",
        ])->assertSessionHasNoErrors();

        $this->assertSame(
            [
                'https://esakip.jemberkab.go.id',
                'https://web.jemberkab.go.id/profil?id=1',
                'https://dinas.jemberkab.go.id:8080',
                'http://lama.jemberkab.go.id',
            ],
            ScanTarget::orderBy('position')->pluck('url')->all()
        );
    }

    /**
     * @return array<string, array{list<string>}>
     */
    public static function semuaDomainProvider(): array
    {
        return ['kosong' => [[]], 'bintang' => [['*']]];
    }

    /**
     * @param  list<string>  $domains
     */
    #[DataProvider('semuaDomainProvider')]
    public function test_semua_domain_diizinkan_jika_daftar_kosong_atau_bintang(array $domains): void
    {
        config(['siprika.allowed_domains' => $domains]);

        $this->post('/scans', ['mode' => 'quick', 'urls' => "contoh.org\nhttps://www.situs-lain.co.id\nbücher.de"])
            ->assertSessionHasNoErrors();

        $this->assertSame(
            ['https://contoh.org', 'https://www.situs-lain.co.id', 'https://xn--bcher-kva.de'],
            ScanTarget::orderBy('position')->pluck('url')->all()
        );

        // Perlindungan SSRF tetap berlaku walaupun semua domain diizinkan
        $this->post('/scans', ['mode' => 'quick', 'urls' => "localhost\n10.0.0.1\nhttp://[::1]/"])
            ->assertSessionHasErrors('urls');
        $this->assertCount(3, session('errors')->get('urls'));

        $this->get('/')->assertSee('Pastikan Anda berwenang memeriksa website tersebut.');
    }

    public function test_daftar_domain_membatasi_dan_ditampilkan_di_form(): void
    {
        $this->post('/scans', ['mode' => 'quick', 'urls' => 'contoh.org'])->assertSessionHasErrors('urls');
        $this->assertStringContainsString('tidak termasuk domain yang diizinkan (jemberkab.go.id)', session('errors')->first('urls'));

        $this->get('/')
            ->assertSee('Domain yang diizinkan: jemberkab.go.id')
            ->assertDontSee('Pastikan Anda berwenang');
    }

    public function test_input_kosong_ditolak(): void
    {
        $this->post('/scans', ['mode' => 'standard', 'urls' => "  \n \n"])
            ->assertSessionHasErrors(['urls' => 'Masukkan minimal satu URL target.']);

        $this->assertSame(0, ScanBatch::count());
    }

    public function test_jumlah_url_melebihi_batas_ditolak(): void
    {
        config(['siprika.max_urls_per_batch' => 2]);

        $this->post('/scans', [
            'mode' => 'standard',
            'urls' => "https://a.jemberkab.go.id\nhttps://b.jemberkab.go.id\nhttps://c.jemberkab.go.id",
        ])->assertSessionHasErrors(['urls' => 'Maksimal 2 URL per pemeriksaan, input berisi 3 URL.']);

        $this->assertSame(0, ScanBatch::count());
    }

    public function test_halaman_antrean_menampilkan_info_batch_dan_target_sesuai_urutan(): void
    {
        $batch = ScanBatch::factory()->create();
        ScanTarget::factory()->for($batch, 'batch')->create(['position' => 2, 'url' => 'https://kedua.jemberkab.go.id', 'status' => ScanTargetStatus::Queued]);
        ScanTarget::factory()->for($batch, 'batch')->create(['position' => 1, 'url' => 'https://pertama.jemberkab.go.id', 'status' => ScanTargetStatus::Running]);

        $this->get(route('scans.show', $batch))
            ->assertOk()
            ->assertSee('Standar')
            ->assertSee($batch->created_at->format('d-m-Y H:i:s'))
            ->assertSee('http-equiv="refresh"', false)
            ->assertSeeInOrder([
                'https://pertama.jemberkab.go.id', 'Sedang diperiksa',
                'https://kedua.jemberkab.go.id', 'Menunggu',
            ]);
    }

    public function test_halaman_antrean_tidak_refresh_jika_semua_selesai(): void
    {
        $batch = ScanBatch::factory()->create();
        ScanTarget::factory()->for($batch, 'batch')->create(['status' => ScanTargetStatus::Completed]);

        $this->get(route('scans.show', $batch))
            ->assertOk()
            ->assertDontSee('http-equiv="refresh"', false);
    }

    public function test_halaman_antrean_batch_tidak_ada_mengembalikan_404(): void
    {
        $this->get('/scans/999')->assertNotFound();
    }

    public function test_target_yang_menunggu_dapat_dibatalkan(): void
    {
        $batch = ScanBatch::factory()->create();
        $running = ScanTarget::factory()->for($batch, 'batch')->create(['position' => 1, 'status' => ScanTargetStatus::Running]);
        $queued = ScanTarget::factory()->for($batch, 'batch')->create(['position' => 2]);

        $this->post(route('scans.cancel', $batch))
            ->assertRedirect(route('scans.show', $batch))
            ->assertSessionHas('status', '1 target yang masih menunggu dibatalkan.');

        $this->assertSame(ScanTargetStatus::Running, $running->fresh()->status);
        $this->assertSame(ScanTargetStatus::Cancelled, $queued->fresh()->status);
    }
}
