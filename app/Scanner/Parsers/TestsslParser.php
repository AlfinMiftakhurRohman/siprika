<?php

namespace App\Scanner\Parsers;

use App\Scanner\Data\FindingData;

/**
 * Mengubah isi file JSON testssl.sh (--jsonfile) menjadi finding protokol lama, rantai sertifikat, dan cipher lemah.
 */
class TestsslParser
{
    /** Kunci katalog yang dinilai testssl.sh */
    public const KEYS = ['tls-chain-incomplete', 'tls-legacy-protocol', 'tls-weak-cipher'];

    private const PROTOCOLS = ['SSLv2', 'SSLv3', 'TLS1', 'TLS1_1', 'TLS1_2', 'TLS1_3'];

    private const LEGACY_PROTOCOLS = ['SSLv2' => 'SSL 2', 'SSLv3' => 'SSL 3', 'TLS1' => 'TLS 1.0', 'TLS1_1' => 'TLS 1.1'];

    /**
     * Hasil "problem" berisi alasan jika testssl.sh gagal di tengah jalan atau tidak menghasilkan data protokol,
     * supaya pemeriksaan tersebut dicatat ERROR, bukan PASS (bagian 22.2).
     *
     * @param  list<array<string, mixed>>  $items
     * @return array{findings: list<FindingData>, summary: string, relevant: list<array<string, mixed>>, problem: string|null}
     */
    public static function parse(array $items, string $endpoint): array
    {
        $legacy = [];
        $weakCiphers = [];
        $chainProblem = null;
        $relevant = [];
        $problem = null;
        $protocolsSeen = 0;

        foreach ($items as $item) {
            $id = (string) ($item['id'] ?? '');
            $finding = (string) ($item['finding'] ?? '');
            $severity = strtoupper((string) ($item['severity'] ?? ''));
            $offered = str_starts_with(strtolower($finding), 'offered');

            if ($id === 'scanProblem' || $severity === 'FATAL') {
                $problem ??= $finding !== '' ? $finding : $id;
                $relevant[] = ['id' => $id, 'finding' => $finding, 'severity' => $severity];

                continue;
            }

            if (in_array($id, self::PROTOCOLS, true)) {
                $protocolsSeen++;
            }

            if (isset(self::LEGACY_PROTOCOLS[$id])) {
                $relevant[] = ['id' => $id, 'finding' => $finding];

                if ($offered) {
                    $legacy[] = self::LEGACY_PROTOCOLS[$id];
                }
            } elseif (str_starts_with($id, 'cert_chain_of_trust')) {
                $relevant[] = ['id' => $id, 'finding' => $finding];

                if (preg_match('/incomplete|failed/i', $finding)) {
                    $chainProblem = $finding;
                }
            } elseif (str_starts_with($id, 'cipherlist_')) {
                $relevant[] = ['id' => $id, 'finding' => $finding, 'severity' => $severity];

                if ($offered && in_array($severity, ['MEDIUM', 'HIGH', 'CRITICAL'], true)) {
                    $weakCiphers[] = substr($id, strlen('cipherlist_'));
                }
            }
        }

        $findings = [];

        if ($legacy !== []) {
            $findings[] = new FindingData('tls-legacy-protocol', 'testssl', 'server menerima '.implode(', ', $legacy).' (testssl.sh)', $endpoint, ['protocols' => $legacy]);
        }

        if ($chainProblem !== null) {
            $findings[] = new FindingData('tls-chain-incomplete', 'testssl', "rantai sertifikat: {$chainProblem} (testssl.sh)", $endpoint, ['cert_chain_of_trust' => $chainProblem]);
        }

        if ($weakCiphers !== []) {
            $findings[] = new FindingData('tls-weak-cipher', 'testssl', 'server menerima cipher lemah kategori '.implode(', ', $weakCiphers).' (testssl.sh)', $endpoint, ['cipher_categories' => $weakCiphers]);
        }

        $summary = $findings === []
            ? 'Tidak ada protokol lama, masalah rantai sertifikat, atau cipher lemah.'
            : implode('; ', array_map(fn (FindingData $f) => $f->detail, $findings)).'.';

        if ($problem === null && $protocolsSeen === 0) {
            $problem = 'hasil tidak berisi data protokol TLS.';
        }

        return ['findings' => $findings, 'summary' => ucfirst($summary), 'relevant' => $relevant, 'problem' => $problem];
    }
}
