<?php

namespace App\Scanner\Network;

interface DnsResolver
{
    /**
     * Resolve record A dan AAAA.
     *
     * @return list<string> daftar IP, kosong jika domain tidak ditemukan
     *
     * @throws \RuntimeException jika permintaan DNS gagal
     */
    public function resolve(string $host): array;
}
