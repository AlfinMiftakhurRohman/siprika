<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * SIPRIKA dipakai lokal tanpa login, sehingga dilindungi dari website lain yang dibuka di browser yang sama:
 * - nama host selain alamat IP, localhost, atau host APP_URL ditolak. Tanpa ini, website penyerang dapat
 *   mengarahkan domainnya ke 127.0.0.1 (DNS rebinding) lalu membaca hasil pemeriksaan atau memulai pemeriksaan;
 * - halaman tidak dapat dibingkai website lain (clickjacking) dan alamatnya tidak dikirim ke website lain.
 */
class ProtectLocalApp
{
    public function handle(Request $request, Closure $next): Response
    {
        if (! self::isTrustedHost($request->getHost())) {
            abort(400, 'Nama host tidak dikenal. Buka SIPRIKA lewat alamat IP (contoh http://127.0.0.1:8000) atau localhost.');
        }

        $response = $next($request);

        $response->headers->set('X-Frame-Options', 'DENY');
        $response->headers->set('Content-Security-Policy', "frame-ancestors 'none'");
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        $response->headers->set('Referrer-Policy', 'same-origin');

        return $response;
    }

    /**
     * Alamat IP tidak dapat diarahkan ulang oleh penyerang, sedangkan *.localhost selalu diarahkan browser ke komputer sendiri.
     */
    public static function isTrustedHost(string $host): bool
    {
        $host = strtolower(trim($host, '[]'));

        return filter_var($host, FILTER_VALIDATE_IP) !== false
            || $host === 'localhost'
            || str_ends_with($host, '.localhost')
            || $host === strtolower((string) parse_url((string) config('app.url'), PHP_URL_HOST));
    }
}
