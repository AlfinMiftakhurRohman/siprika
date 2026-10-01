<?php

namespace App\Scanner\Network;

interface DnsResolver
{
    /**
     * Resolve record A dan AAAA.
     *
     * @return list<string> daftar IP, kosong jika domain tidak ditemukan
     *
     * @throws \RuntimeException jika server DNS tidak dapat dihubungi, contoh koneksi internet laptop terputus
     */
    public function resolve(string $host): array;

    /**
     * Server DNS menjawab pertanyaan tentang domain ini atau domain induknya. False berarti DNS laptop tidak
     * berfungsi, contoh koneksi internet terputus.
     */
    public function isReachable(string $domain): bool;
}
