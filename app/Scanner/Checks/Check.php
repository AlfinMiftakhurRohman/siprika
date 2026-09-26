<?php

namespace App\Scanner\Checks;

use App\Scanner\ScanContext;

interface Check
{
    /**
     * Kunci tahap untuk progress, contoh: http-info.
     */
    public function key(): string;

    /**
     * Nama tahap yang ditampilkan di progress.
     */
    public function label(): string;

    public function run(ScanContext $context): void;
}
