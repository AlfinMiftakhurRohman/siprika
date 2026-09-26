<?php

namespace App\Scanner\Network;

use Carbon\CarbonImmutable;

class TlsReport
{
    /**
     * @param  list<string>  $subjectAltNames
     */
    public function __construct(
        public readonly ?string $subject,
        public readonly array $subjectAltNames,
        public readonly ?string $issuer,
        public readonly ?CarbonImmutable $validFrom,
        public readonly ?CarbonImmutable $validTo,
        public readonly bool $selfSigned,
        // Jumlah sertifikat yang dikirim server
        public readonly int $chainLength,
        public readonly ?string $protocol,
        public readonly ?string $cipher,
        public readonly bool $verified,
        public readonly ?string $verifyError,
    ) {}

    /**
     * Apakah sertifikat berlaku untuk host (SAN, atau CN jika SAN kosong). Mendukung wildcard satu level.
     */
    public function matchesHost(string $host): bool
    {
        $names = $this->subjectAltNames !== [] ? $this->subjectAltNames : array_filter([$this->subject]);
        $host = strtolower($host);

        foreach ($names as $name) {
            $name = strtolower(trim($name));

            if ($name === $host) {
                return true;
            }

            if (str_starts_with($name, '*.')) {
                $suffix = substr($name, 1);
                $label = substr($host, 0, -strlen($suffix));

                if (str_ends_with($host, $suffix) && $label !== '' && ! str_contains($label, '.')) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'subject' => $this->subject,
            'subject_alt_names' => $this->subjectAltNames,
            'issuer' => $this->issuer,
            'valid_from' => $this->validFrom?->toIso8601String(),
            'valid_to' => $this->validTo?->toIso8601String(),
            'self_signed' => $this->selfSigned,
            'chain_length' => $this->chainLength,
            'protocol' => $this->protocol,
            'cipher' => $this->cipher,
            'verified' => $this->verified,
            'verify_error' => $this->verifyError,
        ];
    }
}
