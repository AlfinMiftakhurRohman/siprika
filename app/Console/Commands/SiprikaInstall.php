<?php

namespace App\Console\Commands;

use App\Scanner\Network\DnsResolver;
use App\Scanner\Network\HttpFailure;
use App\Scanner\Network\SafeHttpClient;
use App\Scanner\Network\TlsInspector;
use App\Scanner\Tools\ToolRunner;
use App\Support\TargetUrlNormalizer;
use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;
use RuntimeException;

#[Signature('siprika:install')]
#[Description('Menyiapkan SIPRIKA: file .env, APP_KEY, database SQLite, dan migrasi')]
class SiprikaInstall extends Command
{
    /**
     * Ekstensi PHP yang tidak selalu aktif di php.ini: cURL (koneksi dikunci ke IP yang sudah dicek), SQLite (database),
     * openssl (TLS), serta fileinfo, gd, mbstring, dan zip (Excel).
     */
    public const REQUIRED_EXTENSIONS = ['curl', 'fileinfo', 'gd', 'mbstring', 'openssl', 'pdo_sqlite', 'zip'];

    public function handle(ToolRunner $tools, DnsResolver $dns, TlsInspector $tls): int
    {
        $missing = self::missingExtensions();

        if ($missing !== []) {
            $ini = php_ini_loaded_file();
            $this->components->error('Ekstensi PHP belum aktif: '.implode(', ', $missing).'.');
            $this->line($ini === false
                ? '  Belum ada php.ini. Di folder '.dirname(PHP_BINARY).', salin php.ini-development menjadi php.ini, lalu aktifkan ekstensinya.'
                : "  Buka {$ini}, hapus tanda ; di depan baris ".implode(', ', array_map(fn (string $extension) => "extension={$extension}", $missing)).'.');
            $this->line('  Setelah itu jalankan perintah ini lagi. Lihat PANDUAN.md bagian Memasang PHP.');

            return self::FAILURE;
        }

        if (! File::exists(base_path('.env'))) {
            File::copy(base_path('.env.example'), base_path('.env'));
            $this->components->info('File .env dibuat dari .env.example.');
        }

        if (! preg_match('/^APP_KEY=.+$/m', (string) File::get(base_path('.env')))) {
            $this->call('key:generate', ['--force' => true]);
        }

        if (config('database.default') === 'sqlite') {
            $database = config('database.connections.sqlite.database');

            if ($database !== ':memory:' && ! File::exists($database)) {
                File::put($database, '');
                $this->components->info("Database SQLite dibuat: {$database}");
            }
        }

        $this->call('migrate', ['--force' => true]);

        $this->newLine();
        $this->components->twoColumnDetail('<fg=green;options=bold>Konfigurasi</>');

        $domains = config('siprika.allowed_domains', []);
        $this->components->twoColumnDetail('SCAN_ALLOWED_DOMAINS', (new TargetUrlNormalizer($domains))->allowsAllDomains()
            ? '<fg=yellow>semua domain diizinkan</>'
            : implode(', ', $domains));

        foreach (['nuclei' => 'NUCLEI_PATH', 'testssl' => 'TESTSSL_PATH', 'whatweb' => 'WHATWEB_PATH', 'nmap' => 'NMAP_PATH'] as $tool => $env) {
            $this->components->twoColumnDetail($env, $tools->command($tool) ? implode(' ', $tools->command($tool)) : '<fg=yellow>tidak dipakai (NOT ASSESSED)</>');
        }

        $this->components->twoColumnDetail('ZAP_URL', config('siprika.tools.zap.url')
            ? config('siprika.tools.zap.url').(config('siprika.tools.zap.server_command') ? ', dijalankan otomatis oleh siprika:serve' : '')
            : '<fg=yellow>tidak dipakai (NOT ASSESSED)</>');

        $this->components->twoColumnDetail('AI_ENABLED', config('siprika.ai.enabled') ? 'ya, '.config('siprika.ai.url') : 'tidak (memakai teks katalog)');

        if (config('siprika.ai.enabled')) {
            $this->components->twoColumnDetail('AI_SERVER_COMMAND', config('siprika.ai.server_command') ? 'dijalankan otomatis oleh siprika:serve' : '<fg=yellow>kosong, jalankan llama-server sendiri</>');
        }

        $this->components->twoColumnDetail('Uji verifikasi sertifikat TLS', $this->tlsSelfTest($dns, $tls));

        $this->newLine();
        $this->components->info('Selesai. Jalankan SIPRIKA dengan klik dua kali jalankan-siprika.bat (atau php artisan siprika:serve). Panduan lengkap: PANDUAN.md');

        return self::SUCCESS;
    }

    /**
     * @param  (callable(string): bool)|null  $isLoaded  pengganti extension_loaded untuk test
     * @return list<string>
     */
    public static function missingExtensions(?callable $isLoaded = null): array
    {
        $isLoaded ??= extension_loaded(...);

        return array_values(array_filter(self::REQUIRED_EXTENSIONS, fn (string $extension) => ! $isLoaded($extension)));
    }

    /**
     * Pemeriksaan TLS diuji ke website dengan sertifikat valid sebelum dipakai (bagian 22.5). Jika gagal,
     * CA bundle belum benar dan semua website akan terbaca bersertifikat tidak valid.
     */
    private function tlsSelfTest(DnsResolver $dns, TlsInspector $tls): string
    {
        $host = (string) config('siprika.scan.tls_selftest_host');

        try {
            $ips = $dns->resolve($host);

            if ($ips === []) {
                return "<fg=yellow>tidak dapat diuji</>: {$host} tidak dapat di-resolve";
            }

            $report = $tls->inspect($host, SafeHttpClient::preferIpv4($ips));
        } catch (HttpFailure|RuntimeException $e) {
            return "<fg=yellow>tidak dapat diuji</>: {$host} ({$e->getMessage()})";
        }

        return $report->verified
            ? "<fg=green>berhasil</> ({$host})"
            : "<fg=red>gagal</> ({$host}: {$report->verifyError}). Isi SCAN_CA_BUNDLE dengan CA bundle terbaru, lihat README.";
    }
}
