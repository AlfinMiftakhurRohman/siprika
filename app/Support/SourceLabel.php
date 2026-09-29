<?php

namespace App\Support;

/**
 * Nama sumber temuan dan tool yang mudah dibaca di halaman hasil, contoh "internal" menjadi "Pemeriksaan bawaan".
 * Database tetap menyimpan kode sumber (internal, nuclei, zap, ...).
 */
class SourceLabel
{
    public static function of(string $source): string
    {
        return (string) config("siprika_scanner.source_labels.{$source}", $source);
    }

    /**
     * @param  list<string>  $sources
     */
    public static function list(array $sources): string
    {
        return implode(', ', array_map(self::of(...), $sources));
    }
}
