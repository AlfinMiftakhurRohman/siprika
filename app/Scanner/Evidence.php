<?php

namespace App\Scanner;

/**
 * Penyamaran nilai rahasia sebelum disimpan sebagai evidence (bagian 23.1: potongan isi maksimal
 * 200 karakter dengan nilai rahasia disamarkan). Nilai cookie dan token target tidak pernah disimpan.
 */
class Evidence
{
    private const SNIPPET_LENGTH = 200;

    /**
     * Potongan isi file dengan nilai rahasia disamarkan.
     *
     * @param  string  $mask  env (baris KEY=nilai), php (define/variabel), binary, atau none (pola umum saja)
     */
    public static function snippet(string $body, string $mask): string
    {
        if ($mask === 'binary') {
            return '(file biner)';
        }

        $text = $body;

        if ($mask === 'env') {
            $text = preg_replace('/^(\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*)(.+)$/m', '$1***', $text);
        }

        if ($mask === 'php') {
            $text = preg_replace('/(define\(\s*[\'"][^\'"]+[\'"]\s*,\s*)([\'"]).*?\2/', "$1'***'", $text);
            $text = preg_replace('/(\$\w+\s*=\s*)([\'"]).*?\2/', "$1'***'", $text);
        }

        // Pola rahasia umum pada semua jenis file
        $text = preg_replace('/((?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)\s*[:=]\s*)([^\s;,]+)/i', '$1***', $text);
        $text = preg_replace('/(url\s*=\s*\w+:\/\/)[^@\s]+@/i', '$1***@', $text);

        $text = trim(preg_replace('/\s+/', ' ', $text));

        return mb_substr(mb_convert_encoding($text, 'UTF-8', 'UTF-8'), 0, self::SNIPPET_LENGTH);
    }

    /**
     * Nilai cookie, token sesi, dan JWT disamarkan, hanya namanya yang tersisa. Contoh: laravel-session=***.
     */
    public static function maskSecrets(string $value): string
    {
        $value = preg_replace('/(^|[\s;,])([^\s=;,]+)=([^;\s,]{16,})/', '$1$2=***', $value);
        $value = preg_replace('/\beyJ[A-Za-z0-9_\-]{8,}(?:\.[A-Za-z0-9_\-]+){0,2}/', '***', $value);

        return mb_substr($value, 0, 300);
    }
}
