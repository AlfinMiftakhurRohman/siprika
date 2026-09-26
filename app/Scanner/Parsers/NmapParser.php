<?php

namespace App\Scanner\Parsers;

/**
 * Mengubah output XML Nmap (-oX -) menjadi daftar port terbuka beserta service-nya.
 */
class NmapParser
{
    /**
     * Port berstatus filtered atau closed tidak dihitung terbuka.
     *
     * @return list<array{port: int, service: string|null, product: string|null, version: string|null}>|null null jika XML tidak dapat dibaca
     */
    public static function parse(string $xml): ?array
    {
        $previous = libxml_use_internal_errors(true);
        $document = simplexml_load_string($xml);
        libxml_use_internal_errors($previous);

        if ($document === false) {
            return null;
        }

        $services = [];

        foreach ($document->xpath('//host/ports/port') ?: [] as $port) {
            if ((string) $port->state['state'] !== 'open') {
                continue;
            }

            $services[] = [
                'port' => (int) $port['portid'],
                'service' => ((string) $port->service['name']) ?: null,
                'product' => ((string) $port->service['product']) ?: null,
                'version' => ((string) $port->service['version']) ?: null,
            ];
        }

        return $services;
    }
}
