<?php

namespace App\Scanner\Network;

use RuntimeException;

class SystemDnsResolver implements DnsResolver
{
    public function resolve(string $host): array
    {
        $records = @dns_get_record($host, DNS_A | DNS_AAAA);

        if ($records === false) {
            // Cadangan: resolver sistem operasi (hanya IPv4)
            $ipv4 = @gethostbynamel($host);

            if ($ipv4 !== false) {
                return array_values(array_unique($ipv4));
            }

            // PHP tidak membedakan domain tidak ada (NXDOMAIN) dengan DNS gagal. Jika domain induk
            // dapat di-resolve, DNS berfungsi dan host ini memang tidak ada.
            if ($this->ancestorResolves($host)) {
                return [];
            }

            throw new RuntimeException("domain {$host} tidak ditemukan atau server DNS tidak merespons.");
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
     * Domain induk minimal dua label (contoh jemberkab.go.id, go.id) yang memiliki record NS.
     * TLD tidak dipakai karena sebagian resolver tidak menjawab query NS untuk TLD.
     */
    private function ancestorResolves(string $host): bool
    {
        $labels = explode('.', $host);

        for ($i = 1; $i < count($labels) - 1; $i++) {
            if (! empty(@dns_get_record(implode('.', array_slice($labels, $i)), DNS_NS))) {
                return true;
            }
        }

        return false;
    }
}
