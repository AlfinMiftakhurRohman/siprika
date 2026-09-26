<?php

namespace App\Scanner\Network;

interface TlsInspector
{
    /**
     * Ambil sertifikat (tanpa verifikasi) lalu uji verifikasi ke trust store.
     *
     * @throws HttpFailure jika koneksi TLS tidak dapat dibuat sama sekali
     */
    public function inspect(string $host, string $ip, int $port = 443): TlsReport;

    /**
     * Uji apakah server menerima versi protokol tertentu.
     *
     * @param  string  $version  TLSv1.0, TLSv1.1, TLSv1.2, TLSv1.3
     * @return string accepted, rejected, unsupported (tidak bisa diuji dari mesin ini), atau error
     */
    public function probeProtocol(string $host, string $ip, string $version, int $port = 443): string;
}
