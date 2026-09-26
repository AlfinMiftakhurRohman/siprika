<?php

namespace App\Scanner\Network;

/**
 * Satu respons HTTP beserta rantai redirect yang dilalui.
 */
class HttpExchange
{
    /**
     * @param  array<string, list<string>>  $headers  nama header huruf kecil
     * @param  list<HttpExchange>  $chain  respons sebelum respons ini (redirect)
     */
    public function __construct(
        public readonly string $url,
        public readonly int $status,
        public readonly array $headers,
        public readonly string $body,
        public readonly array $chain = [],
        public readonly ?string $stoppedReason = null,
    ) {}

    public function header(string $name): ?string
    {
        $values = $this->headers[strtolower($name)] ?? [];

        return $values === [] ? null : implode(', ', $values);
    }

    /**
     * @return list<string>
     */
    public function headerValues(string $name): array
    {
        return $this->headers[strtolower($name)] ?? [];
    }

    public function isHttps(): bool
    {
        return str_starts_with(strtolower($this->url), 'https://');
    }

    public function isRedirect(): bool
    {
        return in_array($this->status, [301, 302, 303, 307, 308], true) && $this->header('location') !== null;
    }

    public function title(): ?string
    {
        if (! preg_match('/<title[^>]*>(.*?)<\/title>/is', $this->body, $match)) {
            return null;
        }

        $title = trim(preg_replace('/\s+/', ' ', html_entity_decode(strip_tags($match[1]), ENT_QUOTES | ENT_HTML5, 'UTF-8')));

        return $title === '' ? null : mb_substr($title, 0, 255);
    }

    /**
     * Semua respons dalam rantai, termasuk respons ini.
     *
     * @return list<HttpExchange>
     */
    public function allResponses(): array
    {
        return [...$this->chain, $this];
    }

    /**
     * @return list<array{url: string, status: int}>
     */
    public function redirectSummary(): array
    {
        return array_map(fn (HttpExchange $e) => ['url' => $e->url, 'status' => $e->status], $this->allResponses());
    }
}
