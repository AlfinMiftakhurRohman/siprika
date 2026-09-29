<?php

namespace App\Console\Commands;

use App\Scanner\Checks\NucleiCheck;
use App\Scanner\Parsers\NucleiParser;
use App\Scanner\Tools\ToolRunner;
use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;

#[Signature('siprika:check-nuclei')]
#[Description('Memeriksa bahwa profile_keys Nuclei (Coverage per kunci) sesuai template yang terpasang, misalnya setelah nuclei -ut')]
class SiprikaCheckNuclei extends Command
{
    public function handle(ToolRunner $tools): int
    {
        if ($tools->command('nuclei') === null) {
            $this->components->error('NUCLEI_PATH kosong, Nuclei tidak dipakai.');

            return self::FAILURE;
        }

        $mismatches = 0;

        foreach (config('siprika.tools.nuclei.profiles', []) as $mode => $runs) {
            $paths = [];

            foreach ($runs as $run) {
                // Filter yang sama dengan pemindaian, "-tl" hanya menampilkan daftar template tanpa memindai
                $result = $tools->run('nuclei', ['-tl', '-silent', '-nc', ...NucleiCheck::filterArguments($run)], 120);

                if (! $result->successful && trim($result->output) === '') {
                    $this->components->error("Daftar template Nuclei gagal dibaca: {$result->errorSummary()}");

                    return self::FAILURE;
                }

                array_push($paths, ...array_filter(preg_split('/\R/', $result->output), fn (string $line) => str_ends_with(trim($line), '.yaml')));
            }

            $covered = NucleiParser::keysForTemplates($paths);
            $declared = config("siprika.tools.nuclei.profile_keys.{$mode}", []);

            $this->newLine();
            $this->components->twoColumnDetail("<fg=green;options=bold>Profil {$mode}</>", count($paths).' template');

            foreach (array_values(array_unique([...$declared, ...$covered])) as $key) {
                $status = match (true) {
                    in_array($key, $declared, true) && in_array($key, $covered, true) => '<fg=green>tercakup</>',
                    in_array($key, $declared, true) => '<fg=red>tidak ada template, hapus dari profile_keys</>',
                    default => '<fg=yellow>tercakup, tambahkan ke profile_keys</>',
                };

                $mismatches += str_contains($status, 'profile_keys') ? 1 : 0;
                $this->components->twoColumnDetail($key, $status);
            }
        }

        $this->newLine();

        if ($mismatches > 0) {
            $this->components->warn("{$mismatches} kunci tidak sesuai. Perbarui siprika.tools.nuclei.profile_keys di config/siprika.php supaya Coverage tidak keliru.");

            return self::FAILURE;
        }

        $this->components->info('profile_keys sesuai dengan template Nuclei yang terpasang.');

        return self::SUCCESS;
    }
}
