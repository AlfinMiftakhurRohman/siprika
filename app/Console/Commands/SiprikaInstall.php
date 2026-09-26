<?php

namespace App\Console\Commands;

use App\Scanner\Tools\ToolRunner;
use App\Support\TargetUrlNormalizer;
use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;

#[Signature('siprika:install')]
#[Description('Menyiapkan SIPRIKA: file .env, APP_KEY, database SQLite, dan migrasi')]
class SiprikaInstall extends Command
{
    public function handle(ToolRunner $tools): int
    {
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

        $this->components->twoColumnDetail('AI_ENABLED', config('siprika.ai.enabled') ? 'ya, '.config('siprika.ai.url') : 'tidak (memakai teks katalog)');

        if (config('siprika.ai.enabled')) {
            $this->components->twoColumnDetail('AI_SERVER_COMMAND', config('siprika.ai.server_command') ? 'dijalankan otomatis oleh siprika:serve' : '<fg=yellow>kosong, jalankan llama-server sendiri</>');
        }

        $this->newLine();
        $this->components->info('Selesai. Jalankan: php artisan siprika:serve');

        return self::SUCCESS;
    }
}
