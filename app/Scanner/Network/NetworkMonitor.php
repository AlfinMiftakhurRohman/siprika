<?php

namespace App\Scanner\Network;

use App\Enums\ScanTargetStatus;
use App\Models\ScanTarget;
use App\Scanner\ScanProgress;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Sleep;

/**
 * Koneksi internet laptop yang menjalankan SIPRIKA. Saat offline (server DNS tidak dapat dihubungi, contoh Wi-Fi
 * terputus), antrean dijeda sampai koneksi kembali supaya website berikutnya tidak ikut gagal karena DNS.
 */
class NetworkMonitor
{
    public function __construct(private DnsResolver $dns) {}

    public function isOnline(string $host): bool
    {
        return $this->dns->isReachable($host);
    }

    /**
     * Tunggu sampai laptop online, dicek setiap config siprika.scan.offline_check_interval detik dan paling lama
     * siprika.scan.offline_wait detik. Selama menunggu, progress website menampilkan "Menunggu koneksi internet".
     *
     * @return bool false jika masih offline setelah batas waktu, atau website dibatalkan saat menunggu
     */
    public function waitUntilOnline(ScanTarget $target): bool
    {
        $limit = (int) config('siprika.scan.offline_wait');
        $interval = max(1, (int) config('siprika.scan.offline_check_interval'));
        $waited = 0;

        try {
            while (! $this->isOnline($target->host)) {
                if ($waited >= $limit || $target->refresh()->status !== ScanTargetStatus::Queued) {
                    return false;
                }

                if ($waited === 0) {
                    Log::warning('SIPRIKA menunggu koneksi internet', ['target' => $target->url]);
                    $target->update(['progress' => [[
                        'key' => 'network-wait',
                        'label' => 'Menunggu koneksi internet (terputus sejak '.now()->format('H:i:s').')',
                        'status' => ScanProgress::RUNNING,
                    ]]]);
                }

                Sleep::for($interval)->seconds();
                $waited += $interval;
            }

            return true;
        } finally {
            if ($waited > 0) {
                $target->update(['progress' => null]);
                Log::info('SIPRIKA selesai menunggu koneksi internet', ['target' => $target->url, 'detik' => $waited]);
            }
        }
    }
}
