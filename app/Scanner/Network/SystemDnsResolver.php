<?php

namespace App\Scanner\Network;

use RuntimeException;

class SystemDnsResolver implements DnsResolver
{
    public function resolve(string $host): array
    {
        // Domain yang tidak ada (NXDOMAIN) menghasilkan array kosong, false berarti permintaan DNS gagal
        $records = @dns_get_record($host, DNS_A | DNS_AAAA);

        if ($records === false) {
            // Cadangan: resolver sistem operasi (hanya IPv4)
            $ipv4 = @gethostbynamel($host);

            if ($ipv4 !== false) {
                return array_values(array_unique($ipv4));
            }

            // Server DNS tetap menjawab untuk domain induknya: DNS laptop berfungsi, DNS domain ini yang bermasalah
            if ($this->isReachable($host)) {
                return [];
            }

            throw new RuntimeException("server DNS tidak merespons untuk {$host} maupun domain induknya, kemungkinan koneksi internet laptop terputus.");
        }

        $ips = [];

        foreach ($records as $record) {
            $ip = $record['ip'] ?? $record['ipv6'] ?? null;

            if ($ip !== null) {
                $ips[] = $ip;
            }
        }

        return array_values(array_unique($ips));
    }

    /**
     * Nama acak di bawah domain ini dan setiap domain induknya (contoh siprika-1a2b3c4d.jemberkab.go.id, lalu
     * siprika-5e6f7a8b.go.id) ditanyakan ke server DNS sampai ada yang dijawab. Karena acak, jawabannya pasti dari
     * server DNS, bukan dari cache Windows yang masih tersisa saat internet terputus. Jawaban "nama tidak ada"
     * (array kosong) juga berarti server DNS berfungsi.
     */
    public function isReachable(string $domain): bool
    {
        $labels = explode('.', $domain);

        for ($i = 0; $i < count($labels); $i++) {
            $name = 'siprika-'.bin2hex(random_bytes(4)).'.'.implode('.', array_slice($labels, $i));

            if (@dns_get_record($name, DNS_A) !== false) {
                return true;
            }
        }

        return false;
    }
}
