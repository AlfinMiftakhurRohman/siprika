<?php

namespace Tests\Feature;

use App\Console\Commands\SiprikaInstall;
use App\Console\Commands\SiprikaPackage;
use App\Console\Commands\SiprikaServe;
use App\Enums\ScanMode;
use App\Enums\ScanTargetStatus;
use App\Models\ScanBatch;
use App\Scanner\Network\DnsResolver;
use App\Scanner\Network\TlsInspector;
use Illuminate\Foundation\Testing\RefreshDatabase;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\Process\Process;
use Tests\Support\FakeNetwork;
use Tests\TestCase;

class ConsoleCommandTest extends TestCase
{
    use RefreshDatabase;

    private FakeNetwork $network;

    protected function setUp(): void
    {
        parent::setUp();

        $this->network = new FakeNetwork;
        $this->app->instance(DnsResolver::class, $this->network);
        $this->app->instance(TlsInspector::class, $this->network);
    }

    public function test_siprika_install_menampilkan_konfigurasi(): void
    {
        config([
            'siprika.allowed_domains' => ['jemberkab.go.id'],
            'siprika.tools.nuclei.command' => 'wsl -d Ubuntu -e nuclei',
            'siprika.ai.enabled' => true,
            'siprika.ai.server_command' => null,
            'siprika.tools.zap.url' => 'http://127.0.0.1:8080',
            'siprika.tools.zap.server_command' => 'java -jar zap.jar -daemon',
        ]);

        $this->artisan('siprika:install')
            ->expectsOutputToContain('jemberkab.go.id')
            ->expectsOutputToContain('wsl -d Ubuntu -e nuclei')
            ->expectsOutputToContain('tidak dipakai (NOT ASSESSED)')
            ->expectsOutputToContain('http://127.0.0.1:8080, dijalankan otomatis oleh siprika:serve')
            ->expectsOutputToContain('jalankan llama-server sendiri')
            ->assertSuccessful();
    }

    public function test_siprika_install_mendeteksi_ekstensi_php_yang_belum_aktif(): void
    {
        // PHP yang menjalankan test sudah lengkap
        $this->assertSame([], SiprikaInstall::missingExtensions());

        // PHP baru tanpa gd dan zip: export Excel akan gagal, jadi dilaporkan sejak instalasi
        $this->assertSame(['gd', 'zip'], SiprikaInstall::missingExtensions(fn (string $extension) => ! in_array($extension, ['gd', 'zip'], true)));
    }

    public function test_siprika_install_menguji_verifikasi_sertifikat_ke_website_yang_valid(): void
    {
        config(['siprika.scan.tls_selftest_host' => 'www.google.com']);

        $this->artisan('siprika:install')
            ->expectsOutputToContain('berhasil (www.google.com)')
            ->assertSuccessful();
    }

    public function test_siprika_install_memperingatkan_jika_verifikasi_sertifikat_gagal(): void
    {
        // CA bundle salah: sertifikat valid pun terbaca tidak terverifikasi
        $this->network->tls = FakeNetwork::validCertificate('www.google.com', ['verified' => false, 'verifyError' => 'unable to get local issuer certificate']);

        $this->artisan('siprika:install')
            ->expectsOutputToContain('gagal (www.google.com: unable to get local issuer certificate)')
            ->assertSuccessful();
    }

    public function test_layanan_ai_dengan_path_relatif_dijalankan_dari_folder_siprika(): void
    {
        $arguments = SiprikaServe::serverArguments('artisan serve --port=8081');

        // Program relatif menjadi path lengkap di folder SIPRIKA, argumen lain tetap
        $this->assertSame(base_path('artisan'), $arguments[0]);
        $this->assertSame(['serve', '--port=8081'], array_slice($arguments, 1));

        // Program di PATH atau path lengkap tidak diubah
        $this->assertSame('java', SiprikaServe::serverArguments('java -jar zap.jar')[0]);
        $this->assertSame('D:/tools/llama-server.exe', SiprikaServe::serverArguments('D:/tools/llama-server.exe -m a.gguf')[0]);
        $this->assertSame('C:\\Program Files\\ZAP\\zap.bat', SiprikaServe::serverArguments('"C:\\Program Files\\ZAP\\zap.bat" -daemon')[0]);
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function packageFileProvider(): array
    {
        return [
            'kode aplikasi' => ['app/Scanner/ScanContext.php', true],
            'vendor' => ['vendor/autoload.php', true],
            'aset tampilan' => ['public/build/manifest.json', true],
            'model AI' => ['storage/app/models/qwen2.5-7b-instruct.Q4_K_M.gguf', true],
            'llama.cpp' => ['storage/app/llama.cpp/llama-server.exe', true],
            'contoh env' => ['.env.example', true],
            'gitignore log' => ['storage/logs/.gitignore', true],
            'env rahasia' => ['.env', false],
            'backup env' => ['.env.backup', false],
            'database hasil pemeriksaan' => ['database/database.sqlite', false],
            'log' => ['storage/logs/laravel.log', false],
            'cache view' => ['storage/framework/views/abc.php', false],
            'file kerja tool' => ['storage/app/private/scans/nuclei-x/out.json', false],
            'git' => ['.git/config', false],
            'cache config berisi isi .env' => ['bootstrap/cache/config.php', false],
            'cache route' => ['bootstrap/cache/routes-v7.php', false],
            'daftar package' => ['bootstrap/cache/packages.php', true],
            'panduan' => ['PANDUAN.md', true],
            'peluncur' => ['jalankan-siprika.bat', true],
            'node_modules' => ['node_modules/vite/package.json', false],
            'backslash windows' => ['storage\\logs\\laravel.log', false],
        ];
    }

    #[DataProvider('packageFileProvider')]
    public function test_zip_siprika_tidak_memuat_rahasia_dan_hasil_pemeriksaan(string $path, bool $included): void
    {
        $this->assertSame($included, SiprikaPackage::shouldInclude($path), $path);
    }

    public function test_siprika_package_dry_run_menampilkan_isi_tanpa_membuat_zip(): void
    {
        $this->artisan('siprika:package', ['--dry-run' => true])
            ->expectsOutputToContain('File')
            ->expectsOutputToContain('Ukuran')
            ->assertSuccessful();
    }

    public function test_siprika_serve_berhenti_tanpa_menjalankan_apa_pun_jika_port_sudah_dipakai(): void
    {
        $server = stream_socket_server('tcp://127.0.0.1:0');
        $port = (int) substr(strrchr((string) stream_socket_get_name($server, false), ':'), 1);

        $batch = ScanBatch::create(['mode' => ScanMode::Quick]);
        $running = $batch->targets()->create(['position' => 1, 'url' => 'https://web.jemberkab.go.id', 'host' => 'web.jemberkab.go.id', 'status' => ScanTargetStatus::Running]);

        try {
            $this->artisan('siprika:serve', ['--port' => $port])
                ->expectsOutputToContain("Port {$port} sudah dipakai")
                ->assertFailed();
        } finally {
            fclose($server);
        }

        // SIPRIKA lain yang memakai port itu mungkin masih memeriksa: pemeriksaannya tidak ditandai gagal
        $this->assertSame(ScanTargetStatus::Running, $running->fresh()->status);
    }

    public function test_siprika_serve_memperingatkan_jika_dibuka_ke_jaringan(): void
    {
        // Port sudah dipakai di 127.0.0.1: pengecekan untuk 0.0.0.0 tetap menemukannya, jadi tidak ada yang dijalankan
        $server = stream_socket_server('tcp://127.0.0.1:0');
        $port = (int) substr(strrchr((string) stream_socket_get_name($server, false), ':'), 1);

        try {
            $this->artisan('siprika:serve', ['--host' => '0.0.0.0', '--port' => $port])
                ->expectsOutputToContain('membuka SIPRIKA ke jaringan')
                ->expectsOutputToContain("Port {$port} sudah dipakai")
                ->assertFailed();
        } finally {
            fclose($server);
        }
    }

    public function test_web_server_memakai_opcache_dan_router_laravel(): void
    {
        $this->assertFileExists(SiprikaServe::routerScript());

        $arguments = SiprikaServe::opcacheArguments();

        if ($arguments === []) {
            $this->markTestSkipped('OPcache tidak tersedia pada PHP ini.');
        }

        $process = new Process([PHP_BINARY, ...$arguments, '-r', 'echo (int) is_array(opcache_get_status(false));']);
        $process->run();

        $this->assertSame('1', trim($process->getOutput()), $process->getErrorOutput());
        $this->assertStringNotContainsString('Warning', $process->getErrorOutput().$process->getOutput());
    }

    /**
     * @return array<string, array{string, ?string}>
     */
    public static function serverLogProvider(): array
    {
        return [
            'halaman' => ['[Mon Sep 28 02:20:14 2026] 127.0.0.1:53422 [GET] URI: /targets/27?tab=findings', '09:20:14 GET /targets/27?tab=findings'],
            'kirim form' => ['[Mon Sep 28 02:20:14 2026] 127.0.0.1:53422 [POST] URI: /scans', '09:20:14 POST /scans'],
            'tanggal satu digit' => ['[Tue Sep 1 02:20:14 2026] 127.0.0.1:53422 [GET] URI: /scans/5', '09:20:14 GET /scans/5'],
            'polling progress' => ['[Mon Sep 28 02:20:14 2026] 127.0.0.1:53422 [GET] URI: /scans/22/progress', null],
            'file tidak ada' => ['[Mon Sep 28 09:20:14 2026] 127.0.0.1:53422 [404]: GET /favicon.png', '09:20:14 GET /favicon.png [404]'],
            'aset tampilan' => ['[Mon Sep 28 09:20:14 2026] 127.0.0.1:53422 [200]: GET /build/assets/app-abc.css', null],
            'aset belum berubah' => ['[Mon Sep  1 09:20:14 2026] 127.0.0.1:53422 [304]: GET /favicon.ico', null],
            'koneksi dibuka' => ['[Mon Sep 28 09:20:14 2026] 127.0.0.1:53422 Accepted', null],
            'cek port tanpa request' => ['[Mon Sep 28 10:06:54 2026] 127.0.0.1:62856 Closed without sending a request; it was probably just an unused speculative preconnection', null],
            'koneksi ditutup' => ['[Mon Sep 28 09:20:14 2026] 127.0.0.1:53422 Closing', null],
            'server mulai' => ['[Mon Sep 28 09:20:14 2026] PHP 8.3.32 Development Server (http://127.0.0.1:8000) started', '[Mon Sep 28 09:20:14 2026] PHP 8.3.32 Development Server (http://127.0.0.1:8000) started'],
            'error php' => ['PHP Fatal error:  Allowed memory size exhausted', 'PHP Fatal error:  Allowed memory size exhausted'],
        ];
    }

    #[DataProvider('serverLogProvider')]
    public function test_log_web_server_ringkas_tanpa_menyembunyikan_error(string $line, ?string $expected): void
    {
        $this->travelTo(now()->setTime(9, 20, 14));

        $this->assertSame($expected, SiprikaServe::serverLogLine($line));
    }

    public function test_format_log_web_server_sesuai_output_asli_php(): void
    {
        $router = SiprikaServe::routerScript();
        $server = stream_socket_server('tcp://127.0.0.1:0');
        $address = (string) stream_socket_get_name($server, false);
        fclose($server);

        $process = new Process([PHP_BINARY, '-S', $address, $router], public_path());
        $process->start();

        try {
            // Tunggu server siap, lalu buka satu halaman Laravel dan satu file statis
            for ($i = 0; $i < 50 && ! str_contains($process->getErrorOutput(), 'started'); $i++) {
                usleep(100_000);
            }

            @file_get_contents("http://{$address}/scans/999");
            @file_get_contents("http://{$address}/favicon.ico");
            usleep(300_000);
        } finally {
            $process->stop(1);
        }

        $shown = collect(preg_split('/\R/', $process->getOutput().$process->getErrorOutput()))
            ->map(fn (string $line) => SiprikaServe::serverLogLine($line))
            ->filter()
            ->values();

        $this->assertTrue($shown->contains(fn (string $line) => str_ends_with($line, 'GET /scans/999')), $shown->implode("\n"));
        $this->assertFalse($shown->contains(fn (string $line) => str_contains($line, 'favicon') || str_contains($line, 'Accepted')), $shown->implode("\n"));
    }
}
