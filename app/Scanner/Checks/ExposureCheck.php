<?php

namespace App\Scanner\Checks;

use App\Enums\ObservationStatus;
use App\Scanner\Data\FindingData;
use App\Scanner\Evidence;
use App\Scanner\Network\HttpExchange;
use App\Scanner\Network\HttpFailure;
use App\Scanner\ScanContext;

/**
 * Deteksi file sensitif dan directory listing. Hanya permintaan GET biasa;
 * file dianggap terbuka jika isinya cocok dengan pola, bukan hanya karena status 200.
 */
class ExposureCheck implements Check
{
    public function key(): string
    {
        return 'exposure';
    }

    public function label(): string
    {
        return 'Exposure Detection';
    }

    public function run(ScanContext $context): void
    {
        if ($context->wafBlocked) {
            foreach (['exposure-files' => 'File Sensitif', 'directory-listing' => 'Directory Listing'] as $key => $label) {
                $context->observe($key, $label, 'internal', ObservationStatus::NotAssessed, 'Respons berupa halaman blokir WAF/CDN, bukan website aslinya.');
            }

            return;
        }

        $origin = $context->origin();
        $this->checkFiles($context, $origin);
        $this->checkListing($context, $origin);
    }

    /**
     * Daftar file sensitif yang diperiksa. Mode Cepat hanya memakai sebagian (exposure terbatas).
     *
     * @return list<array{path: string, name: string, pattern: string, mask: string}>
     */
    public static function exposures(ScanContext $context): array
    {
        $exposures = config('siprika_scanner.exposures', []);

        if (! $context->isQuick()) {
            return $exposures;
        }

        $quick = config('siprika_scanner.quick_exposure_paths', []);

        return array_values(array_filter($exposures, fn (array $exposure) => in_array($exposure['path'], $quick, true)));
    }

    /**
     * @return list<string>
     */
    public static function listingPaths(ScanContext $context): array
    {
        return config($context->isQuick() ? 'siprika_scanner.quick_listing_paths' : 'siprika_scanner.listing_paths', []);
    }

    private function checkFiles(ScanContext $context, string $origin): void
    {
        $checked = [];
        $errors = 0;
        $found = [];

        foreach (self::exposures($context) as $exposure) {
            $url = $origin.$exposure['path'];
            $response = $this->request($context, $url);

            if ($response === false) {
                $errors++;
                $checked[] = ['path' => $exposure['path'], 'result' => 'error'];

                continue;
            }

            $matched = $response->status === 200 && preg_match($exposure['pattern'], $response->body) === 1;
            $checked[] = ['path' => $exposure['path'], 'status' => $response->status, 'result' => $matched ? 'found' : 'not_found'];

            if ($matched) {
                $snippet = Evidence::snippet($response->body, $exposure['mask']);
                $found[] = $exposure['name'];
                $context->addFinding(new FindingData(
                    'exposed-sensitive-file', 'internal',
                    "{$exposure['name']} dapat diakses di {$exposure['path']}",
                    $url,
                    ['path' => $exposure['path'], 'snippet' => $snippet],
                ));
            }
        }

        $this->conclude($context, 'exposure-files', 'File Sensitif', $origin, $checked, $errors,
            $found === [] ? null : 'Ditemukan: '.implode(', ', array_unique($found)).'.',
            'path file sensitif diperiksa, tidak ada yang terbuka');
    }

    private function checkListing(ScanContext $context, string $origin): void
    {
        $pattern = config('siprika_scanner.listing_pattern');
        $checked = [];
        $errors = 0;
        $found = [];

        foreach (self::listingPaths($context) as $path) {
            // Halaman utama sudah diambil, tidak perlu diminta ulang
            $response = $path === '/' && $context->homepage?->isRedirectStopped() === false
                ? $context->homepage
                : $this->request($context, $origin.$path);

            if ($response === false) {
                $errors++;
                $checked[] = ['path' => $path, 'result' => 'error'];

                continue;
            }

            $matched = $response->status === 200 && preg_match($pattern, $response->body) === 1;
            $checked[] = ['path' => $path, 'status' => $response->status, 'result' => $matched ? 'found' : 'not_found'];

            if ($matched) {
                $found[] = $path;
                $context->addFinding(new FindingData('directory-listing', 'internal', "directory listing aktif pada {$path}", $origin.$path, ['path' => $path]));
            }
        }

        $this->conclude($context, 'directory-listing', 'Directory Listing', $origin, $checked, $errors,
            $found === [] ? null : 'Directory listing aktif pada: '.implode(', ', $found).'.',
            'direktori diperiksa, directory listing tidak aktif');
    }

    /**
     * Simpulkan status: FAIL jika ada temuan, ERROR jika ada path yang gagal diperiksa
     * (timeout tidak pernah dianggap PASS, bagian 22.2), selain itu PASS.
     *
     * @param  list<array<string, mixed>>  $checked
     */
    private function conclude(ScanContext $context, string $key, string $label, string $origin, array $checked, int $errors, ?string $failSummary, string $passText): void
    {
        $raw = ['origin' => $origin, 'mode' => $context->mode->value, 'checked' => $checked];
        $scope = $context->isQuick() ? ' Mode Cepat: exposure terbatas, hanya path umum yang diperiksa.' : '';

        if ($failSummary !== null) {
            $context->observe($key, $label, 'internal', ObservationStatus::Fail, $failSummary.$scope, $raw);
        } elseif ($checked === []) {
            $context->observe($key, $label, 'internal', ObservationStatus::NotAssessed, 'Tidak ada path yang dikonfigurasi untuk diperiksa.', $raw);
        } elseif ($errors === count($checked)) {
            $context->observe($key, $label, 'internal', ObservationStatus::Error, 'Semua permintaan gagal karena kesalahan jaringan.', $raw);
        } elseif ($errors > 0) {
            $context->observe($key, $label, 'internal', ObservationStatus::Error, (count($checked) - $errors)." {$passText}, tetapi {$errors} path gagal diperiksa karena kesalahan jaringan.".$scope, $raw);
        } else {
            $context->observe($key, $label, 'internal', ObservationStatus::Pass, count($checked)." {$passText}.".$scope, $raw);
        }
    }

    private function request(ScanContext $context, string $url): HttpExchange|false
    {
        usleep((int) config('siprika.scan.request_delay_ms') * 1000);

        try {
            return $context->http->get($url, followRedirects: false, maxBytes: 64 * 1024);
        } catch (HttpFailure) {
            return false;
        }
    }
}
