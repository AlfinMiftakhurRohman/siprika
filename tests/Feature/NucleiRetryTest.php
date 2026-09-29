<?php

namespace Tests\Feature;

use App\Enums\ObservationStatus;
use App\Enums\ScanMode;
use App\Enums\ScanTargetStatus;
use App\Models\ScanObservation;
use App\Models\ScanTarget;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Process\PendingProcess;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Process;
use Illuminate\Support\Sleep;
use Tests\Support\FakeNetwork;
use Tests\Support\InteractsWithScanner;
use Tests\TestCase;

/**
 * Website yang kewalahan atau membatasi request Nuclei: request yang gagal diulang pada kecepatan lebih rendah,
 * dan hasil yang tetap tidak lengkap dicatat ERROR, bukan diam-diam dianggap lengkap.
 */
class NucleiRetryTest extends TestCase
{
    use InteractsWithScanner;
    use RefreshDatabase;

    private const HOME = 'https://web.jemberkab.go.id/';

    /** @var list<array{rate: string|null, elog: string|null, mhe: string|null, tags: string|null, ids: string|null, templates: list<string>|null}> */
    private array $runs = [];

    protected function setUp(): void
    {
        parent::setUp();

        $this->setUpScanner();
        Sleep::fake();
        config(['siprika.tools.nuclei.command' => 'nuclei']);

        FakeNetwork::http([
            self::HOME => Http::response('<title>Web</title>', 200, self::secureHeaders()),
            'http://web.jemberkab.go.id/' => Http::response('', 301, ['Location' => self::HOME]),
        ]);
    }

    private static function nucleiResult(string $template, string $severity = 'info'): string
    {
        return json_encode(['template-id' => $template, 'info' => ['name' => $template, 'severity' => $severity, 'tags' => ['misconfig']], 'matched-at' => self::HOME.$template]);
    }

    /**
     * Satu baris -elog Nuclei untuk request yang gagal.
     */
    private static function failure(string $template): string
    {
        return json_encode(['template' => "/home/siprika/nuclei-templates/http/{$template}.yaml", 'type' => 'http', 'input' => self::HOME, 'error' => 'context deadline exceeded', 'kind' => 'network-temporary-error']);
    }

    /**
     * Nuclei palsu: percobaan ke-n menulis request gagal ke -elog dan mengembalikan hasilnya.
     *
     * @param  list<array{output?: list<string>, errors?: list<string>, then?: callable}>  $attempts
     */
    private function fakeNuclei(array $attempts): void
    {
        Process::fake(function (PendingProcess $process) use ($attempts) {
            $command = (array) $process->command;
            $option = function (string $flag) use ($command): ?string {
                $position = array_search($flag, $command, true);

                return $position === false ? null : ($command[$position + 1] ?? null);
            };

            $attempt = $attempts[count($this->runs)] ?? [];
            $templates = $option('-t');
            $this->runs[] = [
                'rate' => $option('-rl'),
                'elog' => $option('-elog'),
                'mhe' => $option('-mhe'),
                'tags' => $option('-tags'),
                'ids' => $option('-id'),
                'templates' => $templates !== null ? file($process->path.DIRECTORY_SEPARATOR.$templates, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : null,
            ];

            file_put_contents($process->path.DIRECTORY_SEPARATOR.$option('-elog'), implode("\n", $attempt['errors'] ?? []));
            ($attempt['then'] ?? fn () => null)();

            return Process::result(implode("\n", $attempt['output'] ?? []));
        });
    }

    private function nuclei(ScanTarget $target): ScanObservation
    {
        return $target->observations->firstWhere('check_key', 'nuclei');
    }

    public function test_run_tanpa_request_gagal_tidak_diulang_dan_folder_kerja_dihapus(): void
    {
        $this->fakeNuclei([['output' => [self::nucleiResult('tech-detect')]]]);

        $target = $this->scan();

        $this->assertCount(1, $this->runs);
        $this->assertSame(['rate' => '15', 'elog' => 'nuclei-errors-1.jsonl', 'mhe' => '30'], array_intersect_key($this->runs[0], array_flip(['rate', 'elog', 'mhe'])));
        $this->assertSame([['run' => 1, 'retry' => false, 'rate_limit' => 15, 'failed_requests' => 0]], $this->nuclei($target)->raw['attempts']);
        $this->assertSame(15, $this->nuclei($target)->raw['rate_limit']);
        $this->assertSame(ScanTargetStatus::Completed, $target->status);
        $this->assertSame([], File::glob(storage_path('app/private/scans/nuclei-*')));
        Sleep::assertNeverSlept();
    }

    public function test_hanya_template_yang_gagal_diulang_pada_kecepatan_rendah_dan_hasil_digabung(): void
    {
        $this->fakeNuclei([
            ['output' => [self::nucleiResult('a-detect')], 'errors' => [self::failure('x-panel'), self::failure('x-panel'), self::failure('y-config')]],
            // Pengulangan menemukan hasil yang tadinya terlewat, hasil lama yang sama tidak menjadi ganda
            ['output' => [self::nucleiResult('a-detect'), self::nucleiResult('x-panel', 'medium')]],
        ]);

        $target = $this->scan();
        $nuclei = $this->nuclei($target);

        $this->assertCount(2, $this->runs);
        $this->assertSame('10', $this->runs[1]['rate']);
        $this->assertSame(['/home/siprika/nuclei-templates/http/x-panel.yaml', '/home/siprika/nuclei-templates/http/y-config.yaml'], $this->runs[1]['templates']);
        $this->assertNull($this->runs[1]['tags'], 'Hanya template yang gagal, bukan seluruh profil');

        $this->assertNotSame(ObservationStatus::Error, $nuclei->status);
        $this->assertStringContainsString('Template yang gagal diulang pada 10 request per detik karena 3 request ke website gagal', $nuclei->summary);
        $this->assertSame(['a-detect', 'x-panel'], array_column($nuclei->raw['results'], 'template'));
        $this->assertTrue($target->findings->contains('finding_key', 'nuclei:x-panel'));
        $this->assertSame(ScanTargetStatus::Completed, $target->status);
        Sleep::assertNeverSlept();
    }

    public function test_banyak_request_gagal_tanpa_pemblokiran_hanya_template_yang_gagal_diulang(): void
    {
        // Seperti uji e-sakip pada 15 request/detik: puluhan request timeout, tetapi website tidak memblokir
        $this->fakeNuclei([
            ['errors' => [...array_fill(0, 40, self::failure('x-panel')), ...array_fill(0, 22, self::failure('y-config')), ...self::expectedFailures()]],
            ['output' => [self::nucleiResult('x-panel', 'medium')]],
        ]);

        $target = $this->scan();

        $this->assertCount(2, $this->runs);
        $this->assertSame('10', $this->runs[1]['rate']);
        $this->assertCount(2, $this->runs[1]['templates'], 'Hanya dua template yang gagal, bukan seluruh profil');
        Sleep::assertNeverSlept();

        $this->assertStringContainsString('Template yang gagal diulang pada 10 request per detik karena 62 request ke website gagal', $this->nuclei($target)->summary);
        $this->assertSame(ScanTargetStatus::Completed, $target->status);
    }

    public function test_website_yang_memblokir_diulang_seluruhnya_setelah_jeda(): void
    {
        // Website membatasi saat Nuclei berjalan, lalu pulih selama jeda
        Sleep::whenFakingSleep(fn () => FakeNetwork::http([self::HOME => Http::response('<title>Web</title>', 200, self::secureHeaders())]));

        $this->fakeNuclei([
            ['then' => fn () => FakeNetwork::http([self::HOME => Http::response('Too Many Requests', 429)])],
            ['output' => [self::nucleiResult('x-panel', 'medium')]],
        ]);

        $target = $this->scan();

        $this->assertCount(2, $this->runs);
        $this->assertSame('5', $this->runs[1]['rate']);
        $this->assertNull($this->runs[1]['templates']);
        $this->assertSame($this->runs[0]['tags'], $this->runs[1]['tags'], 'Seluruh profil diulang');
        Sleep::assertSleptTimes(1);

        $this->assertStringContainsString('Run diulang pada 5 request per detik karena website membalas 429 Too Many Requests', $this->nuclei($target)->summary);
        $this->assertSame(ScanTargetStatus::Completed, $target->status);
    }

    public function test_website_yang_tetap_memblokir_dicatat_error_dan_partial_tetapi_temuan_disimpan(): void
    {
        // Setelah Nuclei mulai, website membalas 429 untuk semua permintaan
        $block = fn () => FakeNetwork::http([self::HOME => Http::response('Too Many Requests', 429)]);

        $this->fakeNuclei([
            ['output' => [self::nucleiResult('git-config', 'medium')], 'then' => $block],
        ]);

        $target = $this->scan();
        $nuclei = $this->nuclei($target);

        // Setelah jeda website masih memblokir: tidak diulang supaya tidak dibebani ribuan request lagi
        $this->assertCount(1, $this->runs);
        Sleep::assertSleptTimes(1);
        $this->assertSame(ObservationStatus::Error, $nuclei->status);
        $this->assertStringContainsString('429 Too Many Requests', $nuclei->summary);
        $this->assertStringContainsString('masih memblokir setelah jeda 30 detik', $nuclei->summary);
        $this->assertTrue($nuclei->raw['incomplete']);
        $this->assertSame(ScanTargetStatus::Partial, $target->status);
        $this->assertTrue($target->findings->contains('finding_key', 'nuclei:git-config'));
    }

    /**
     * Baris -elog yang memang wajar gagal, seperti hasil uji e-sakip: probe tcp ke port web, port lain yang tertutup,
     * probe TLS lama yang ditolak, dan request https ke port 80.
     */
    private static function expectedFailures(): array
    {
        return [
            ...array_fill(0, 39, json_encode(['template' => '/t/network/cves/2004/CVE-2004-0437.yaml', 'type' => 'tcp', 'input' => 'web.jemberkab.go.id', 'address' => 'web.jemberkab.go.id:443', 'error' => 'i/o timeout', 'kind' => 'network-temporary-error'])),
            json_encode(['template' => '/t/http/exposed-panels/hpe-autopass-panel.yaml', 'type' => 'http', 'input' => 'https://web.jemberkab.go.id:5814/autopass', 'address' => 'web.jemberkab.go.id:5814', 'error' => 'context deadline exceeded', 'kind' => 'network-temporary-error']),
            json_encode(['template' => '/t/http/misconfiguration/sccm.yaml', 'type' => 'http', 'input' => 'https://web.jemberkab.go.id:80/SMS_DP_SMSPKG$/Datalib', 'address' => 'web.jemberkab.go.id:80', 'error' => 'tls: first record does not look like a TLS handshake']),
            json_encode(['template' => 'deprecated-tls', 'type' => 'ssl', 'input' => 'web.jemberkab.go.id', 'address' => 'web.jemberkab.go.id:443', 'error' => 'handshake failure', 'kind' => 'unknown-error']),
            json_encode(['template' => '/t/dns/tlsa-record-detect.yaml', 'type' => 'dns', 'input' => 'web.jemberkab.go.id', 'address' => 'web.jemberkab.go.id:', 'error' => 'no answer']),
        ];
    }

    public function test_kegagalan_wajar_di_luar_website_tidak_diulang_dan_tidak_membuat_partial(): void
    {
        $this->fakeNuclei([['output' => [self::nucleiResult('tech-detect')], 'errors' => self::expectedFailures()]]);

        $target = $this->scan();
        $nuclei = $this->nuclei($target);

        $this->assertCount(1, $this->runs, 'Tidak diulang');
        $this->assertSame([['run' => 1, 'retry' => false, 'rate_limit' => 15, 'failed_requests' => 0, 'other_failures' => 43]], $nuclei->raw['attempts']);
        $this->assertNotSame(ObservationStatus::Error, $nuclei->status);
        $this->assertSame(ScanTargetStatus::Completed, $target->status);
    }

    public function test_sedikit_request_yang_tetap_gagal_setelah_diulang_hanya_dicatat(): void
    {
        $this->fakeNuclei([
            ['output' => [self::nucleiResult('a-detect')], 'errors' => [self::failure('x-panel'), self::failure('x-panel')]],
            ['errors' => [self::failure('x-panel'), self::failure('x-panel')]],
        ]);

        $target = $this->scan();
        $nuclei = $this->nuclei($target);

        $this->assertCount(2, $this->runs);
        $this->assertNotSame(ObservationStatus::Error, $nuclei->status);
        $this->assertStringContainsString('2 request tetap gagal setelah diulang', $nuclei->summary);
        $this->assertSame([2, 2], array_column($nuclei->raw['attempts'], 'failed_requests'));
        $this->assertSame(ScanTargetStatus::Completed, $target->status);
    }

    public function test_banyak_request_yang_tetap_gagal_setelah_diulang_dicatat_error(): void
    {
        $this->fakeNuclei([
            ['errors' => array_fill(0, 12, self::failure('x-panel'))],
            ['errors' => array_fill(0, 10, self::failure('x-panel'))],
        ]);

        $target = $this->scan();

        $this->assertSame(ObservationStatus::Error, $this->nuclei($target)->status);
        $this->assertStringContainsString('10 request ke website gagal', $this->nuclei($target)->summary);
        $this->assertSame(ScanTargetStatus::Partial, $target->status);
    }

    public function test_kecepatan_kembali_normal_untuk_run_berikutnya_jika_website_tidak_memblokir(): void
    {
        // Mode Cepat punya dua run; run pertama sempat gagal sedikit
        $this->fakeNuclei([
            ['errors' => [self::failure('x-panel')]],
            [],
            [],
        ]);

        $this->scan(mode: ScanMode::Quick);

        $this->assertSame(['15', '10', '15'], array_column($this->runs, 'rate'));
    }

    public function test_website_yang_pernah_memblokir_tetap_diperlambat_untuk_run_berikutnya(): void
    {
        Sleep::whenFakingSleep(fn () => FakeNetwork::http([self::HOME => Http::response('<title>Web</title>', 200, self::secureHeaders())]));

        $this->fakeNuclei([
            ['then' => fn () => FakeNetwork::http([self::HOME => Http::response('Too Many Requests', 429)])],
            [],
            [],
        ]);

        $this->scan(mode: ScanMode::Quick);

        $this->assertSame(['15', '5', '5'], array_column($this->runs, 'rate'));
    }

    public function test_run_berikutnya_tidak_dijalankan_jika_website_masih_memblokir(): void
    {
        $this->fakeNuclei([
            ['then' => fn () => FakeNetwork::http([self::HOME => Http::response('Too Many Requests', 429)])],
        ]);

        $target = $this->scan(mode: ScanMode::Quick);

        $this->assertCount(1, $this->runs, 'Run kedua Mode Cepat tidak membebani website yang memblokir');
        $this->assertSame(ScanTargetStatus::Partial, $target->status);
    }

    public function test_template_yang_hanya_dicatat_idnya_diulang_dengan_id(): void
    {
        $idOnly = json_encode(['template' => 'tech-detect', 'type' => 'http', 'input' => self::HOME, 'error' => 'context deadline exceeded', 'kind' => 'network-temporary-error']);
        $this->fakeNuclei([['errors' => [$idOnly, self::failure('x-panel')]], []]);

        $this->scan();

        $this->assertSame('tech-detect', $this->runs[1]['ids']);
        $this->assertSame(['/home/siprika/nuclei-templates/http/x-panel.yaml'], $this->runs[1]['templates']);
    }
}
