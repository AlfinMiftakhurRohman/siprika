<?php

namespace Tests\Feature;

use App\Enums\ObservationStatus;
use App\Enums\ScanMode;
use App\Enums\ScanTargetStatus;
use App\Models\ScanTarget;
use App\Scanner\Evidence;
use App\Scanner\Parsers\NmapParser;
use App\Scanner\Parsers\NucleiParser;
use App\Scanner\Parsers\TestsslParser;
use App\Scanner\Parsers\WhatWebParser;
use App\Scanner\Tools\RunningTool;
use App\Scanner\Tools\ToolResult;
use App\Scanner\Tools\ToolRunner;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Process\PendingProcess;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Process;
use Tests\Support\FakeNetwork;
use Tests\Support\InteractsWithScanner;
use Tests\TestCase;

class ExternalToolsTest extends TestCase
{
    use InteractsWithScanner;
    use RefreshDatabase;

    private const HOME = 'https://web.jemberkab.go.id/';

    protected function setUp(): void
    {
        parent::setUp();

        $this->setUpScanner();

        // Halaman aman kecuali HSTS, supaya deduplikasi dengan Nuclei bisa diuji
        $headers = self::secureHeaders();
        unset($headers['Strict-Transport-Security']);

        FakeNetwork::http([
            self::HOME => Http::response('<title>Web</title>', 200, $headers),
            'http://web.jemberkab.go.id/' => Http::response('', 301, ['Location' => self::HOME]),
        ]);
    }

    public function test_hasil_nuclei_dipetakan_ke_katalog_dan_digabung_dengan_scanner_lain(): void
    {
        config(['siprika.tools.nuclei.command' => 'nuclei']);

        $lines = [
            ['template-id' => 'http-missing-security-headers', 'matcher-name' => 'strict-transport-security', 'info' => ['name' => 'HTTP Missing Security Headers', 'severity' => 'info', 'tags' => ['misconfig', 'headers']], 'matched-at' => self::HOME],
            ['template-id' => 'tech-detect', 'matcher-name' => 'nginx', 'info' => ['name' => 'Wappalyzer Technology Detection', 'severity' => 'info', 'tags' => ['tech']], 'matched-at' => self::HOME],
            ['template-id' => 'CVE-2023-1234', 'info' => ['name' => 'Contoh CMS Vulnerability', 'severity' => 'high', 'tags' => ['cve', 'cve2023'], 'classification' => ['cve-id' => ['cve-2023-1234'], 'cvss-score' => 8.8], 'remediation' => 'Upgrade.'], 'matched-at' => self::HOME.'x'],
            ['template-id' => 'git-config', 'info' => ['name' => 'Git Config Disclosure', 'severity' => 'medium', 'tags' => ['exposure', 'config', 'git']], 'matched-at' => self::HOME.'.git/config', 'extracted-results' => ['[core] password=rahasia123']],
            ['template-id' => 'some-info', 'info' => ['name' => 'Informasi Lain', 'severity' => 'info', 'tags' => ['misc']], 'matched-at' => self::HOME],
        ];

        Process::fake(['*' => Process::result(implode("\n", array_map('json_encode', $lines)))]);

        $target = $this->scan();

        Process::assertRan(function (PendingProcess $process) {
            $command = self::commandOf($process);

            return str_starts_with($command, 'nuclei -u https://web.jemberkab.go.id')
                && str_contains($command, '-no-stdin')
                && preg_match('/-mt \d+s/', $command) === 1
                && str_contains($command, '-rl 15 -c 15')
                && str_contains($command, '-tags exposure,misconfig,tech,ssl,cve')
                && str_contains($command, 'intrusive,dos,fuzz,default-login');
        });

        $this->assertSame(ScanTargetStatus::Completed, $target->status);

        // missing-hsts dari pemeriksaan bawaan dan Nuclei menjadi satu finding dengan dua sumber
        $hsts = $target->findings->firstWhere('finding_key', 'missing-hsts');
        $this->assertSame(['internal', 'nuclei'], $hsts->sources);
        $this->assertCount(2, $hsts->evidences);

        // Kolom Kerawanan memakai penjelasan pemeriksaan bawaan, bukan teks "template Nuclei ... cocok pada ..."
        $this->assertSame(
            'Lemahnya mekanisme kriptografi aplikasi (header Strict-Transport-Security tidak ditemukan pada respons HTTPS)',
            $target->riskItems->firstWhere('finding_key', 'missing-hsts')->vulnerability,
        );

        $cve = $target->findings->firstWhere('finding_key', 'nuclei:CVE-2023-1234');
        $this->assertSame('CVE-2023-1234', $cve->cve);
        $this->assertSame(8.8, $cve->cvss);

        // Severity high: dampak 4, kemungkinan 3 (bagian 24.4)
        $risk = $target->riskItems->firstWhere('finding_key', 'nuclei:CVE-2023-1234');
        $this->assertSame(17, $risk->inherent_risk);
        $this->assertSame('Aplikasi tidak update (Contoh CMS Vulnerability (CVE-2023-1234))', $risk->vulnerability);

        $exposure = $target->findings->firstWhere('finding_key', 'exposed-sensitive-file');
        $this->assertStringNotContainsString('rahasia123', $exposure->evidences->first()->raw['snippet']);

        // Severity info tampil di Findings tetapi tidak menjadi baris Risk Register
        $this->assertNotNull($target->findings->firstWhere('finding_key', 'nuclei:some-info'));
        $this->assertNull($target->riskItems->firstWhere('finding_key', 'nuclei:some-info'));

        $this->assertNull($target->findings->firstWhere('finding_key', 'nuclei:tech-detect'));
        // "nginx" dari Nuclei digabung dengan "Nginx" dari header Server, tidak dobel
        $names = array_map('strtolower', array_column($target->overview['technologies'], 'name'));
        $this->assertSame(1, count(array_keys($names, 'nginx')));
    }

    public function test_mode_cepat_memakai_nuclei_profil_ringan_dan_tidak_menjalankan_tool_mode_standar(): void
    {
        config([
            'siprika.tools.nuclei.command' => 'nuclei',
            'siprika.tools.testssl.command' => 'testssl.sh',
            'siprika.tools.whatweb.command' => 'whatweb',
            'siprika.tools.nmap.command' => 'nmap',
        ]);
        Process::fake(['*' => Process::result('')]);

        $target = $this->scan(mode: ScanMode::Quick);

        // Profil ringan: template informasi penting, lalu tag Mode Cepat hanya severity high dan critical
        Process::assertRan(fn (PendingProcess $process) => str_contains(self::commandOf($process), '-id tech-detect,waf-detect,http-missing-security-headers,'));
        Process::assertRan(fn (PendingProcess $process) => str_contains(self::commandOf($process), '-tags exposure,misconfig,tech,ssl -s high,critical -etags'));
        Process::assertNotRan(fn (PendingProcess $process) => str_contains(self::commandOf($process), 'cve'));

        foreach (['testssl.sh', 'whatweb', 'nmap'] as $tool) {
            Process::assertNotRan(fn (PendingProcess $process) => str_starts_with(self::commandOf($process), $tool));
        }

        $observation = $target->observations->firstWhere('check_key', 'nuclei');
        $this->assertSame(ObservationStatus::Pass, $observation->status);
        $this->assertStringContainsString('10 template informasi', $observation->summary);
        $this->assertStringContainsString('tag exposure, misconfig, tech, ssl (severity high, critical)', $observation->summary);
    }

    public function test_hasil_nuclei_yang_hanya_informasi_tidak_dicatat_fail(): void
    {
        config(['siprika.tools.nuclei.command' => 'nuclei']);
        $line = ['template-id' => 'http-missing-security-headers', 'matcher-name' => 'permissions-policy', 'info' => ['name' => 'HTTP Missing Security Headers', 'severity' => 'info', 'tags' => ['misconfig', 'headers', 'generic']], 'matched-at' => self::HOME];
        Process::fake(['*' => Process::result(json_encode($line))]);

        $target = $this->scan();

        $this->assertSame(ObservationStatus::Info, $target->observations->firstWhere('check_key', 'nuclei')->status);
        $this->assertNotNull($target->findings->firstWhere('finding_key', 'nuclei:http-missing-security-headers'));
        $this->assertNull($target->riskItems->firstWhere('finding_key', 'nuclei:http-missing-security-headers'));
    }

    public function test_temuan_cookie_nuclei_dinilai_dengan_aturan_insecure_cookie_dan_nilai_cookie_disamarkan(): void
    {
        config(['siprika.tools.nuclei.command' => 'nuclei']);
        $cookieTags = ['misconfig', 'http', 'cookie', 'generic', 'vuln'];
        // Pola output asli Nuclei dari website Laravel di belakang Cloudflare
        $lines = [
            ['template-id' => 'cookies-without-secure', 'info' => ['name' => 'Cookies without Secure attribute - Detect', 'severity' => 'info', 'tags' => $cookieTags], 'matched-at' => 'web.jemberkab.go.id', 'extracted-results' => ['XSRF-TOKEN', 'laravel-session']],
            ['template-id' => 'cookies-without-httponly', 'info' => ['name' => 'Cookies without HttpOnly attribute - Detect', 'severity' => 'info', 'tags' => $cookieTags], 'matched-at' => 'web.jemberkab.go.id', 'extracted-results' => ['XSRF-TOKEN']],
            ['template-id' => 'missing-cookie-samesite-strict', 'info' => ['name' => 'Missing Cookie SameSite Strict', 'severity' => 'info', 'tags' => $cookieTags], 'matched-at' => self::HOME,
                'extracted-results' => ['XSRF-TOKEN=eyJpdiI6IklISlhXN1d3WUlLRmlGWllDcUlGMGc9PSIsInZhbHVlIjoi%3D; expires=Fri, 25 Sep 2026 11:43:07 GMT; Max-Age=7200; path=/; samesite=lax laravel-session=eyJpdiI6IksyNklJRVJkeTVFS0tDVmI3Q3R2eHc9PSIsInZhbHVlIjoi%3D; path=/; httponly; samesite=lax']],
        ];
        Process::fake(['*' => Process::result(implode("\n", array_map('json_encode', $lines)))]);

        $target = $this->scan();

        // Semua cookie wajib Secure: menjadi insecure-cookie (bagian 23.1)
        $cookie = $target->findings->firstWhere('finding_key', 'insecure-cookie');
        $this->assertSame(['nuclei'], $cookie->sources);
        $this->assertSame(['cookie XSRF-TOKEN, laravel-session tanpa Secure (Nuclei)'], $cookie->evidences->pluck('detail')->all());
        $this->assertSame(7, $target->riskItems->firstWhere('finding_key', 'insecure-cookie')->inherent_risk);

        // XSRF-TOKEN memang dibaca JavaScript dan SameSite=Lax sudah cukup: tetap informasi
        $this->assertSame('info', $target->findings->firstWhere('finding_key', 'nuclei:cookies-without-httponly')->severity->value);
        $this->assertNull($target->riskItems->firstWhere('finding_key', 'nuclei:cookies-without-httponly'));
        $this->assertNull($target->riskItems->firstWhere('finding_key', 'nuclei:missing-cookie-samesite-strict'));

        // Nilai cookie sesi target tidak tersimpan di evidence
        $raw = json_encode($target->findings->firstWhere('finding_key', 'nuclei:missing-cookie-samesite-strict')->evidences->first()->raw);
        $this->assertStringNotContainsString('eyJpdiI6', $raw);
        $this->assertStringContainsString('laravel-session=***', $raw);
        $this->assertStringContainsString('samesite=lax', $raw);

        // Cookie sesi tanpa HttpOnly tetap menjadi temuan
        $parsed = NucleiParser::parse(json_encode(['template-id' => 'cookies-without-httponly', 'info' => ['severity' => 'info', 'tags' => $cookieTags], 'matched-at' => self::HOME, 'extracted-results' => ['PHPSESSID', 'XSRF-TOKEN']]));
        $this->assertSame('insecure-cookie', $parsed['findings'][0]->key);
        $this->assertSame('cookie PHPSESSID tanpa HttpOnly (Nuclei)', $parsed['findings'][0]->detail);

        $this->assertSame('token=*** Max-Age=7200', Evidence::maskSecrets('token=abcdefghijklmnop1234 Max-Age=7200'));
        $this->assertSame('Bearer ***', Evidence::maskSecrets('Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig'));
    }

    public function test_nuclei_yang_melewati_batas_waktu_tetap_menyimpan_temuan_dan_dicatat_error(): void
    {
        config(['siprika.tools.nuclei.command' => 'nuclei']);
        $line = ['template-id' => 'git-config', 'info' => ['name' => 'Git Config Disclosure', 'severity' => 'medium', 'tags' => ['exposure', 'config', 'git']], 'matched-at' => self::HOME.'.git/config'];

        // Proses terpotong batas waktu, tetapi satu hasil sudah sempat ditulis
        $this->app->instance(ToolRunner::class, new class(json_encode($line)) extends ToolRunner
        {
            public function __construct(private string $partialOutput) {}

            public function start(string $tool, array $arguments, int $timeout, ?string $workingDirectory = null): RunningTool
            {
                return new RunningTool(fn () => new ToolResult(false, $this->partialOutput, '', null, true));
            }
        });

        $target = $this->scan();

        $observation = $target->observations->firstWhere('check_key', 'nuclei');
        $this->assertSame(ObservationStatus::Error, $observation->status);
        $this->assertStringContainsString('melewati batas waktu', $observation->summary);
        $this->assertSame(['nuclei'], $target->findings->firstWhere('finding_key', 'exposed-sensitive-file')->sources);
        $this->assertSame(ScanTargetStatus::Partial, $target->status);
    }

    public function test_nuclei_berjalan_di_latar_belakang_sementara_tool_lain_dikerjakan(): void
    {
        config([
            'siprika.tools.nuclei.command' => 'nuclei',
            'siprika.tools.testssl.command' => 'testssl.sh',
            'siprika.tools.whatweb.command' => 'whatweb',
            'siprika.tools.nmap.command' => 'nmap',
        ]);
        $started = [];
        $nuclei = json_encode(['template-id' => 'git-config', 'info' => ['name' => 'Git Config Disclosure', 'severity' => 'medium', 'tags' => ['exposure', 'config']], 'matched-at' => self::HOME.'.git/config']);
        $testssl = self::fixture('testssl-diskominfo.json');

        Process::fake(function (PendingProcess $process) use (&$started, $nuclei, $testssl) {
            $tool = explode(' ', self::commandOf($process))[0];
            $started[] = $tool;

            if ($tool === 'testssl.sh') {
                file_put_contents($process->path.DIRECTORY_SEPARATOR.'testssl.json', $testssl);
            }

            return Process::result($tool === 'nuclei' ? $nuclei : '');
        });

        $target = $this->scan();

        // Nuclei dimulai lebih dulu, tool lain dijalankan sambil menunggu (bagian 26: tetap satu website)
        $this->assertSame(['nuclei', 'nmap', 'testssl.sh', 'whatweb'], $started);

        // Hasil Nuclei dibaca terakhir dan tetap lengkap
        $keys = $target->observations->pluck('check_key')->all();
        $this->assertGreaterThan(array_search('testssl', $keys, true), array_search('nuclei', $keys, true));
        $this->assertSame(['nuclei'], $target->findings->firstWhere('finding_key', 'exposed-sensitive-file')->sources);
        $this->assertSame(['testssl'], $target->findings->firstWhere('finding_key', 'tls-legacy-protocol')->sources);

        // Semua tahap progress selesai
        $this->assertSame([], collect($target->progress)->whereIn('status', ['running', 'waiting'])->pluck('key')->all());
    }

    public function test_nuclei_yang_belum_dipasang_tidak_ditunggu(): void
    {
        $target = $this->scan();

        $nuclei = $target->observations->firstWhere('check_key', 'nuclei');
        $this->assertSame(ObservationStatus::NotAssessed, $nuclei->status);
        $this->assertSame('skipped', collect($target->progress)->firstWhere('key', 'nuclei')['status']);
    }

    public function test_label_progress_menampilkan_semua_tahap_yang_berjalan(): void
    {
        $target = new ScanTarget(['progress' => [
            ['key' => 'nuclei', 'label' => 'Nuclei', 'status' => 'running', 'weight' => 1300, 'started_at' => microtime(true)],
            ['key' => 'testssl', 'label' => 'testssl.sh', 'status' => 'running', 'weight' => 80, 'started_at' => microtime(true)],
            ['key' => 'whatweb', 'label' => 'WhatWeb', 'status' => 'waiting', 'weight' => 10, 'started_at' => null],
        ]]);

        $this->assertSame('Nuclei + testssl.sh', $target->currentStep());
    }

    public function test_lama_tool_latar_belakang_dihitung_sampai_proses_selesai(): void
    {
        config(['siprika.tools.nmap.command' => PHP_BINARY]);

        $running = app(ToolRunner::class)->start('nmap', ['-r', 'echo "selesai";'], 30);

        // Proses selesai jauh sebelum hasilnya dibaca, contoh Nuclei yang selesai saat testssl.sh berjalan.
        // poll() dipanggil berkala seperti di antara pemeriksaan lain.
        for ($i = 0; $i < 30; $i++) {
            usleep(50_000);
            $running->poll();
        }

        sleep(2);
        $result = $running->wait();

        $this->assertTrue($result->successful);
        $this->assertStringContainsString('selesai', $result->output);
        $this->assertLessThan(2.5, $result->seconds);
    }

    public function test_output_parsial_tetap_dikembalikan_saat_tool_melewati_batas_waktu(): void
    {
        config(['siprika.tools.nmap.command' => PHP_BINARY]);

        $result = app(ToolRunner::class)->run('nmap', ['-r', 'echo "baris1\n"; flush(); sleep(30);'], 2);

        $this->assertTrue($result->timedOut);
        $this->assertStringContainsString('baris1', $result->output);
    }

    public function test_nuclei_gagal_dicatat_error_dan_status_partial(): void
    {
        config(['siprika.tools.nuclei.command' => 'nuclei']);
        Process::fake(['*' => Process::result('', 'nuclei: command not found', 1)]);

        $target = $this->scan();

        $this->assertSame(ScanTargetStatus::Partial, $target->status);
        $observation = $target->observations->firstWhere('check_key', 'nuclei');
        $this->assertSame(ObservationStatus::Error, $observation->status);
        $this->assertStringContainsString('command not found', $observation->summary);
    }

    public function test_perintah_tool_mendukung_prefix_wsl_dan_path_berspasi(): void
    {
        config(['siprika.tools.testssl.command' => 'wsl testssl.sh', 'siprika.tools.nmap.command' => '"C:/Program Files/Nmap/nmap.exe"']);

        $runner = app(ToolRunner::class);

        $this->assertSame(['wsl', 'testssl.sh'], $runner->command('testssl'));
        $this->assertSame(['C:/Program Files/Nmap/nmap.exe'], $runner->command('nmap'));
        $this->assertNull($runner->command('whatweb'));
    }

    /**
     * Tool palsu yang menulis file hasil ke folder kerja, seperti testssl.sh --jsonfile dan whatweb --log-json.
     */
    private static function fakeToolWritingFile(string $fileName, string $contents): void
    {
        Process::fake(function (PendingProcess $process) use ($fileName, $contents) {
            file_put_contents($process->path.DIRECTORY_SEPARATOR.$fileName, $contents);

            return Process::result('');
        });
    }

    private static function fixture(string $name): string
    {
        return (string) file_get_contents(base_path("tests/Fixtures/{$name}"));
    }

    public function test_output_asli_testssl_dibaca_dan_digabung_dengan_pemeriksaan_bawaan(): void
    {
        config(['siprika.tools.testssl.command' => 'testssl.sh']);
        // Output asli testssl.sh: TLS 1.1 offered, cipher OBSOLETED (LOW) offered, rantai sertifikat passed
        self::fakeToolWritingFile('testssl.json', self::fixture('testssl-diskominfo.json'));
        $this->network->protocols['TLSv1.1'] = 'accepted';

        $target = $this->scan();

        Process::assertRan(fn (PendingProcess $process) => str_contains(self::commandOf($process), '--ip 93.184.216.34')
            && str_contains(self::commandOf($process), 'web.jemberkab.go.id:443'));

        $observation = $target->observations->firstWhere('check_key', 'testssl');
        $this->assertSame(ObservationStatus::Fail, $observation->status);
        $this->assertStringContainsString('TLS 1.1', $observation->summary);

        // Pemeriksaan bawaan dan testssl.sh menemukan hal yang sama: satu finding dengan dua sumber
        $legacy = $target->findings->firstWhere('finding_key', 'tls-legacy-protocol');
        $this->assertSame(['internal', 'testssl'], $legacy->sources);
        $this->assertCount(2, $legacy->evidences);

        // Cipher OBSOLETED berseverity LOW dan rantai "passed" bukan temuan
        $keys = $target->findings->pluck('finding_key')->all();
        $this->assertNotContains('tls-weak-cipher', $keys);
        $this->assertNotContains('tls-chain-incomplete', $keys);
    }

    public function test_testssl_yang_gagal_di_tengah_jalan_tidak_dianggap_pass(): void
    {
        config(['siprika.tools.testssl.command' => 'testssl.sh']);
        self::fakeToolWritingFile('testssl.json', json_encode([
            ['id' => 'engine_problem', 'severity' => 'WARN', 'finding' => 'No engine or GOST support'],
            ['id' => 'scanProblem', 'severity' => 'FATAL', 'finding' => "Can't connect to web.jemberkab.go.id:443"],
        ]));

        $target = $this->scan();

        $observation = $target->observations->firstWhere('check_key', 'testssl');
        $this->assertSame(ObservationStatus::Error, $observation->status);
        $this->assertStringContainsString("Can't connect", $observation->summary);
        $this->assertSame(ScanTargetStatus::Partial, $target->status);

        // File hasil tanpa data protokol juga bukan PASS
        $this->assertNotNull(TestsslParser::parse([['id' => 'service', 'severity' => 'INFO', 'finding' => 'HTTP']], self::HOME)['problem']);
        $this->assertNull(TestsslParser::parse(json_decode(self::fixture('testssl-diskominfo.json'), true), self::HOME)['problem']);
    }

    public function test_output_asli_whatweb_dibaca_tanpa_mengikuti_redirect(): void
    {
        config(['siprika.tools.whatweb.command' => 'whatweb']);
        self::fakeToolWritingFile('whatweb.json', self::fixture('whatweb-diskominfo.json'));

        $target = $this->scan();

        Process::assertRan(fn (PendingProcess $process) => str_contains(self::commandOf($process), '--follow-redirect=never')
            && str_contains(self::commandOf($process), '--log-json=whatweb.json'));

        $this->assertSame(ObservationStatus::Info, $target->observations->firstWhere('check_key', 'whatweb')->status);
        $whatweb = collect($target->overview['technologies'])->where('source', 'whatweb')->pluck('name')->all();
        $this->assertEqualsCanonicalizing(['Bootstrap', 'CloudFlare'], $whatweb);
    }

    public function test_output_asli_nmap_dibaca(): void
    {
        config(['siprika.tools.nmap.command' => 'nmap']);
        Process::fake(['*' => Process::result(self::fixture('nmap-diskominfo.xml'))]);

        $target = $this->scan();

        // Port filtered (8000, 8888) tidak dihitung terbuka
        $this->assertSame([80, 443, 8080, 8443], array_column($target->overview['open_ports'], 'port'));
        $this->assertSame('Cloudflare http proxy', $target->overview['open_ports'][0]['product']);
        $this->assertSame(ObservationStatus::Info, $target->observations->firstWhere('check_key', 'service-version')->status);
    }

    public function test_exposure_nuclei_berseverity_low_tidak_dinaikkan_menjadi_file_sensitif(): void
    {
        config(['siprika.tools.nuclei.command' => 'nuclei']);
        $lines = [
            // Pola asli: .editorconfig bertag exposure dengan severity low
            ['template-id' => 'editor-exposure', 'info' => ['name' => 'Editor Configuration File - Detect', 'severity' => 'low', 'tags' => ['config', 'exposure', 'vuln']], 'matched-at' => self::HOME.'.editorconfig'],
            ['template-id' => 'git-config', 'info' => ['name' => 'Git Config Disclosure', 'severity' => 'medium', 'tags' => ['exposure', 'config', 'git']], 'matched-at' => self::HOME.'.git/config'],
        ];
        Process::fake(['*' => Process::result(implode("\n", array_map('json_encode', $lines)))]);

        $target = $this->scan();

        $this->assertSame([self::HOME.'.git/config'], $target->findings->firstWhere('finding_key', 'exposed-sensitive-file')->evidences->pluck('endpoint')->all());

        // Dampak mengikuti severity Nuclei (low = 2, kemungkinan 3), bukan IR 23 File Sensitif
        $editor = $target->riskItems->firstWhere('finding_key', 'nuclei:editor-exposure');
        $this->assertSame(10, $editor->inherent_risk);
        $this->assertSame(23, $target->riskItems->firstWhere('finding_key', 'exposed-sensitive-file')->inherent_risk);
    }

    public function test_kolom_kerawanan_memuat_endpoint_lain_yang_hanya_ditemukan_nuclei(): void
    {
        config(['siprika.tools.nuclei.command' => 'nuclei']);
        FakeNetwork::http([
            self::HOME => Http::response('<title>Web</title>', 200, self::secureHeaders()),
            'http://web.jemberkab.go.id/' => Http::response('', 301, ['Location' => self::HOME]),
            'https://web.jemberkab.go.id/.env' => Http::response("APP_KEY=base64:rahasia\nDB_PASSWORD=rahasia\n", 200),
        ]);
        $exposure = fn (string $id, string $path) => ['template-id' => $id, 'info' => ['name' => $id, 'severity' => 'medium', 'tags' => ['exposure', 'config']], 'matched-at' => self::HOME.$path];
        Process::fake(['*' => Process::result(implode("\n", array_map('json_encode', [$exposure('laravel-env', '.env'), $exposure('git-config', '.git/config')])))]);

        $target = $this->scan();
        $vulnerability = $target->riskItems->firstWhere('finding_key', 'exposed-sensitive-file')->vulnerability;

        // .env ditemukan pemeriksaan bawaan dan Nuclei: satu penjelasan; .git/config hanya Nuclei: tetap tampil
        $this->assertStringContainsString('.env', $vulnerability);
        $this->assertStringNotContainsString('laravel-env', $vulnerability);
        $this->assertStringContainsString('git-config', $vulnerability);
    }

    public function test_hasil_waf_detect_bukan_teknologi_dan_nama_teknologi_tidak_ganda(): void
    {
        config(['siprika.tools.nuclei.command' => 'nuclei']);
        $info = fn (string $id, ?string $matcher, string $name, array $tags) => array_filter(['template-id' => $id, 'matcher-name' => $matcher, 'info' => ['name' => $name, 'severity' => 'info', 'tags' => $tags], 'matched-at' => self::HOME]);
        $lines = [
            // Pola asli dari server LiteSpeed: waf-detect cocok dengan tiga WAF sekaligus
            $info('waf-detect', 'varnish', 'WAF Detection', ['waf', 'tech', 'misc']),
            $info('waf-detect', 'alertlogic', 'WAF Detection', ['waf', 'tech', 'misc']),
            $info('s3-detect', null, 'Detect Amazon-S3 Bucket', ['aws', 's3', 'bucket', 'tech']),
            $info('tech-detect', 'font-awesome', 'Wappalyzer Technology Detection', ['tech']),
            $info('tech-detect', 'google-font-api', 'Wappalyzer Technology Detection', ['tech']),
            $info('php-detect', null, 'PHP Detect', ['tech', 'php']),
            $info('fingerprinthub-web-fingerprints', 'laravel-framework', 'FingerprintHub Technology Fingerprint', ['tech']),
            $info('fingerprinthub-web-fingerprints', 'laravel', 'FingerprintHub Technology Fingerprint', ['tech']),
        ];
        Process::fake(['*' => Process::result(implode("\n", array_map('json_encode', $lines)))]);

        $target = $this->scan();
        $names = array_column($target->overview['technologies'], 'name');

        $this->assertNotContains('Varnish', $names);
        $this->assertNotContains('Alertlogic', $names);
        $this->assertNotContains('Detect Amazon-S3 Bucket', $names);
        $this->assertContains('Font Awesome', $names);
        $this->assertContains('Google Font Api', $names);
        // "PHP Detect" dan "laravel-framework" sama dengan PHP dan Laravel
        $this->assertSame(1, count(array_filter($names, fn ($n) => stripos($n, 'php') === 0)));
        $this->assertSame(1, count(array_filter($names, fn ($n) => stripos($n, 'laravel') === 0)));
    }

    public function test_check_nuclei_mencocokkan_profile_keys_dengan_template_terpasang(): void
    {
        config(['siprika.tools.nuclei.command' => 'nuclei']);
        $quick = "http/misconfiguration/http-missing-security-headers.yaml\nssl/deprecated-tls.yaml\nssl/weak-cipher-suites.yaml\nssl/expired-ssl.yaml\nssl/untrusted-root-certificate.yaml\nhttp/exposures/configs/git-config.yaml";
        Process::fake(function (PendingProcess $process) use ($quick) {
            $command = self::commandOf($process);

            // Profil Standar kehilangan template cipher lemah tetapi mendapat template directory listing
            return Process::result(str_contains($command, '-tags exposure,misconfig,tech,ssl,cve')
                ? str_replace('ssl/weak-cipher-suites.yaml', 'http/miscellaneous/dir-listing.yaml', $quick)."\nhttp/misconfiguration/cookies-without-secure.yaml"
                : $quick);
        });
        config(['siprika_scanner.nuclei_map.dir-listing' => 'directory-listing']);

        $this->assertSame(1, Artisan::call('siprika:check-nuclei'));
        $output = Artisan::output();

        $this->assertMatchesRegularExpression('/Profil standard.*tls-weak-cipher \.+ tidak ada template, hapus dari profile_keys/s', $output);
        $this->assertMatchesRegularExpression('/directory-listing \.+ tercakup, tambahkan ke profile_keys/', $output);
        $this->assertMatchesRegularExpression('/Profil quick.*tls-weak-cipher \.+ tercakup\s/s', $output);

        // Daftar template memakai filter yang sama dengan pemindaian, tanpa memindai target
        Process::assertRan(fn (PendingProcess $process) => str_starts_with(self::commandOf($process), 'nuclei -tl')
            && str_contains(self::commandOf($process), '-etags intrusive,dos,fuzz')
            && ! str_contains(self::commandOf($process), '-u '));
    }

    public function test_check_nuclei_berhasil_jika_profile_keys_sesuai(): void
    {
        config([
            'siprika.tools.nuclei.command' => 'nuclei',
            'siprika.tools.nuclei.profiles' => ['quick' => [['ids' => ['weak-cipher-suites']]]],
            'siprika.tools.nuclei.profile_keys' => ['quick' => ['tls-weak-cipher']],
        ]);
        Process::fake(['*' => Process::result("ssl/weak-cipher-suites.yaml\n")]);

        $this->artisan('siprika:check-nuclei')
            ->expectsOutputToContain('profile_keys sesuai')
            ->assertSuccessful();
    }

    public function test_path_tool_dari_env_dikosongkan_saat_test(): void
    {
        // phpunit.xml mengosongkan path tool supaya test tidak pernah menjalankan scanner sungguhan
        $this->assertSame('', (string) env('NUCLEI_PATH'));
        $this->assertSame('', (string) env('TESTSSL_PATH'));
        $this->assertSame('', (string) env('WHATWEB_PATH'));
        $this->assertSame('', (string) env('NMAP_PATH'));
        $this->assertSame('', (string) env('ZAP_URL'));
    }

    public function test_output_testssl_dipetakan_ke_kunci_finding(): void
    {
        $parsed = TestsslParser::parse([
            ['id' => 'SSLv3', 'severity' => 'OK', 'finding' => 'not offered'],
            ['id' => 'TLS1', 'severity' => 'LOW', 'finding' => 'offered (deprecated)'],
            ['id' => 'TLS1_1', 'severity' => 'LOW', 'finding' => 'offered (deprecated)'],
            ['id' => 'TLS1_2', 'severity' => 'OK', 'finding' => 'offered'],
            ['id' => 'cert_chain_of_trust', 'severity' => 'CRITICAL', 'finding' => 'failed (chain incomplete).'],
            ['id' => 'cipherlist_3DES_IDEA', 'severity' => 'MEDIUM', 'finding' => 'offered'],
            ['id' => 'cipherlist_NULL', 'severity' => 'OK', 'finding' => 'not offered'],
        ], self::HOME);

        $keys = array_map(fn ($finding) => $finding->key, $parsed['findings']);

        $this->assertSame(['tls-legacy-protocol', 'tls-chain-incomplete', 'tls-weak-cipher'], $keys);
        $this->assertStringContainsString('TLS 1.0, TLS 1.1', $parsed['findings'][0]->detail);
        $this->assertStringContainsString('3DES_IDEA', $parsed['findings'][2]->detail);
    }

    public function test_output_whatweb_dan_nmap_dapat_dibaca(): void
    {
        $technologies = WhatWebParser::parse([[
            'target' => self::HOME,
            'plugins' => [
                'WordPress' => ['version' => ['6.4.2']],
                'Title' => ['string' => ['Web']],
                'JQuery' => [],
                'Country' => ['string' => ['INDONESIA']],
                'X-Powered-By' => ['string' => ['PHP/8.3.33']],
            ],
        ]]);

        // X-Powered-By adalah nama header, bukan teknologi
        $this->assertSame(['WordPress', 'JQuery'], array_column($technologies, 'name'));
        $this->assertSame('6.4.2', $technologies[0]['version']);

        $xml = '<?xml version="1.0"?><nmaprun><host><ports>'
            .'<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.24.0"/></port>'
            .'<port protocol="tcp" portid="8080"><state state="closed"/><service name="http-proxy"/></port>'
            .'<port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>'
            // Pola asli Nmap untuk LiteSpeed: service http lewat TLS
            .'<port protocol="tcp" portid="8443"><state state="open"/><service name="http" product="LiteSpeed httpd" tunnel="ssl"/></port>'
            .'</ports></host></nmaprun>';

        $this->assertSame([
            ['port' => 80, 'service' => 'http', 'product' => 'nginx', 'version' => '1.24.0'],
            ['port' => 443, 'service' => 'https', 'product' => null, 'version' => null],
            ['port' => 8443, 'service' => 'https', 'product' => 'LiteSpeed httpd', 'version' => null],
        ], NmapParser::parse($xml));

        $this->assertNull(NmapParser::parse('bukan xml'));
    }

    public function test_cipher_tls_lama_dari_nuclei_hanya_menjadi_cipher_lemah_jika_termasuk_kategori_lemah(): void
    {
        $line = fn (string $matcher, ?array $extracted) => json_encode(array_filter([
            'template-id' => 'weak-cipher-suites',
            'matcher-name' => $matcher,
            'info' => ['name' => 'Weak Cipher Suites Detection', 'severity' => 'low', 'tags' => ['ssl', 'tls', 'misconfig']],
            'type' => 'ssl',
            'matched-at' => 'web.jemberkab.go.id:443',
            'extracted-results' => $extracted,
        ], fn ($value) => $value !== null));
        $findings = fn (string $output) => NucleiParser::parse($output)['findings'];

        // Output asli j-krep.jemberkab.go.id: AES-CBC di TLS 1.1 sudah tercakup tls-legacy-protocol
        $aesCbc = $line('tls-1.1', ['[tls11 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA]']);
        $this->assertSame([], $findings($aesCbc));
        $this->assertCount(1, NucleiParser::parse($aesCbc)['results'], 'Hasil tetap tercatat untuk Coverage');

        foreach (['TLS_RSA_WITH_3DES_EDE_CBC_SHA', 'TLS_ECDHE_RSA_WITH_RC4_128_SHA', 'TLS_RSA_WITH_NULL_SHA', 'TLS_DH_anon_WITH_AES_128_CBC_SHA', 'TLS_RSA_EXPORT_WITH_DES40_CBC_SHA'] as $cipher) {
            $weak = $findings($line('tls-1.0', ["[tls10 {$cipher}]"]));
            $this->assertSame(['tls-weak-cipher'], array_map(fn ($finding) => $finding->key, $weak), $cipher);
            $this->assertStringContainsString($cipher, $weak[0]->detail);
        }

        // Nuclei tanpa nama cipher: tetap dianggap lemah supaya tidak terlewat
        $this->assertSame(['tls-weak-cipher'], array_map(fn ($finding) => $finding->key, $findings($line('tls-1.0', null))));
    }
}
