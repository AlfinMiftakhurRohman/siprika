<?php

namespace App\Scanner\Data;

/**
 * Satu temuan dari satu scanner. Temuan dengan kunci sama digabung saat disimpan.
 * Untuk kunci katalog, judul/deskripsi/severity diambil dari katalog jika tidak diisi.
 */
class FindingData
{
    /**
     * @param  array<string, mixed>|null  $raw
     */
    public function __construct(
        public readonly string $key,
        public readonly string $source,
        public readonly string $detail,
        public readonly ?string $endpoint = null,
        public readonly ?array $raw = null,
        public readonly ?string $title = null,
        public readonly ?string $severity = null,
        public readonly ?string $description = null,
        public readonly ?string $recommendation = null,
        public readonly ?string $cve = null,
        public readonly ?float $cvss = null,
    ) {}
}
