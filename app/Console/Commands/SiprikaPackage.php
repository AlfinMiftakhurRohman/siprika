<?php

namespace App\Console\Commands;

use FilesystemIterator;
use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;
use ZipArchive;

#[Signature('siprika:package {--output= : Lokasi file zip, bawaan di samping folder SIPRIKA} {--dry-run : Hanya tampilkan isi tanpa membuat zip}')]
#[Description('Membuat zip SIPRIKA siap pakai (termasuk model AI dan llama.cpp) tanpa .env, database hasil pemeriksaan, dan log')]
class SiprikaPackage extends Command
{
    /**
     * Tidak ikut dibagikan: rahasia (.env), hasil pemeriksaan website (database), log, cache,
     * file kerja sementara, dan folder pengembangan. Path relatif dengan garis miring biasa.
     */
    private const EXCLUDED = [
        '#^\.git/#',
        '#^node_modules/#',
        '#^\.(claude|idea|vscode|cursor|codex|zed|nova|phpunit\.cache)/#',
        '#^\.env($|\.(?!example$))#',
        '#^database/.*\.sqlite(-journal|-wal|-shm)?$#',
        '#^storage/logs/(?!\.gitignore$)#',
        '#^storage/framework/(cache|sessions|views|testing)/(?!.*\.gitignore$)#',
        '#^storage/app/private/(?!\.gitignore$)#',
        // Cache config (php artisan config:cache atau optimize) berisi isi .env dan path laptop ini
        '#^bootstrap/cache/(?!\.gitignore$|packages\.php$|services\.php$)#',
        '#^public/hot$#',
        '#^(CLAUDE|AGENTS)\.md$#',
        '#^\.phpunit\.result\.cache$#',
    ];

    /** File besar yang sudah terkompresi (model, program) disimpan tanpa kompresi supaya cepat */
    private const STORE_ABOVE_BYTES = 20 * 1024 * 1024;

    public function handle(): int
    {
        $files = $this->files();
        $bytes = array_sum(array_column($files, 1));

        $this->components->twoColumnDetail('File', (string) count($files));
        $this->components->twoColumnDetail('Ukuran', round($bytes / 1024 / 1024 / 1024, 2).' GB');
        $this->components->twoColumnDetail('Model AI', is_dir(storage_path('app/models')) ? 'ikut (storage/app/models)' : '<fg=yellow>tidak ada</>');
        $this->components->twoColumnDetail('Tidak ikut', '.env, database hasil pemeriksaan, log, cache');

        if ($this->option('dry-run')) {
            return self::SUCCESS;
        }

        $output = (string) ($this->option('output') ?: dirname(base_path()).DIRECTORY_SEPARATOR.'siprika-'.now()->format('Ymd-His').'.zip');
        $zip = new ZipArchive;

        if ($zip->open($output, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
            $this->components->error("Zip tidak dapat dibuat: {$output}");

            return self::FAILURE;
        }

        foreach ($files as $relative => [$path, $size]) {
            $entry = 'siprika/'.$relative;
            $zip->addFile($path, $entry);

            if ($size > self::STORE_ABOVE_BYTES) {
                $zip->setCompressionName($entry, ZipArchive::CM_STORE);
            }
        }

        $this->components->task('Menulis zip (file model besar, bisa beberapa menit)', fn () => $zip->close());
        $this->components->info("Zip dibuat: {$output}");
        $this->line('  Penerima mengikuti PANDUAN.md: ekstrak zip, lalu klik dua kali jalankan-siprika.bat.');

        return self::SUCCESS;
    }

    public static function shouldInclude(string $relativePath): bool
    {
        $path = str_replace('\\', '/', $relativePath);

        foreach (self::EXCLUDED as $pattern) {
            if (preg_match($pattern, $path)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Hanya path dan ukuran yang disimpan (bukan objek SplFileInfo) supaya hemat memori untuk ribuan file vendor.
     *
     * @return array<string, array{0: string, 1: int}> path relatif => [path lengkap, ukuran]
     */
    private function files(): array
    {
        $root = base_path();
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
        $files = [];

        foreach ($iterator as $file) {
            /** @var SplFileInfo $file */
            $relative = str_replace('\\', '/', substr($file->getPathname(), strlen($root) + 1));

            if ($file->isFile() && self::shouldInclude($relative)) {
                $files[$relative] = [$file->getPathname(), $file->getSize()];
            }
        }

        ksort($files);

        return $files;
    }
}
