<?php

namespace App\Scanner;

use App\Enums\ScanMode;
use App\Jobs\ProcessScanTarget;
use App\Models\ScanBatch;
use App\Models\ScanTarget;
use Illuminate\Support\Facades\DB;

/**
 * Membuat batch pemeriksaan dan memasukkan setiap website ke antrean sesuai urutan input (bagian 2).
 */
class ScanQueue
{
    /**
     * @param  list<array{url: string, host: string}>  $targets
     */
    public function start(ScanMode $mode, array $targets): ScanBatch
    {
        $batch = DB::transaction(function () use ($mode, $targets) {
            $batch = ScanBatch::create(['mode' => $mode]);

            foreach (array_values($targets) as $index => $target) {
                $batch->targets()->create([
                    'position' => $index + 1,
                    'url' => $target['url'],
                    'host' => $target['host'],
                ]);
            }

            return $batch;
        });

        foreach ($batch->targets as $target) {
            ProcessScanTarget::dispatch($target);
        }

        return $batch;
    }

    /**
     * Pindai ulang website dengan mode yang sama sebagai batch baru. Hasil lama tetap tersimpan.
     *
     * @param  iterable<ScanTarget>  $targets
     */
    public function restart(ScanMode $mode, iterable $targets): ScanBatch
    {
        $list = [];

        foreach ($targets as $target) {
            $list[] = ['url' => $target->url, 'host' => $target->host];
        }

        return $this->start($mode, $list);
    }
}
