<?php

namespace App\Support;

/**
 * Lama waktu yang mudah dibaca. Aturan yang sama dipakai resources/js/app.js untuk lama berjalan yang diperbarui tiap detik.
 */
class Duration
{
    /**
     * Contoh "45 detik", "22 menit 23 detik", "1 jam 5 menit".
     */
    public static function format(int $seconds): string
    {
        $seconds = max(0, $seconds);

        if ($seconds < 60) {
            return "{$seconds} detik";
        }

        $hours = intdiv($seconds, 3600);
        $minutes = intdiv($seconds % 3600, 60);

        if ($hours > 0) {
            return $minutes > 0 ? "{$hours} jam {$minutes} menit" : "{$hours} jam";
        }

        $rest = $seconds % 60;

        return $rest > 0 ? "{$minutes} menit {$rest} detik" : "{$minutes} menit";
    }

    /**
     * Perkiraan sisa waktu dibulatkan ke atas per menit, contoh "± 10 menit" atau "< 1 menit".
     */
    public static function approximate(int $seconds): string
    {
        if ($seconds < 60) {
            return '< 1 menit';
        }

        $minutes = (int) ceil($seconds / 60);

        return '± '.($minutes >= 60 ? self::format($minutes * 60) : "{$minutes} menit");
    }
}
