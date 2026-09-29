<?php

namespace App\Ai;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;
use RuntimeException;

/**
 * Klien llama-server (llama.cpp) lewat endpoint OpenAI-compatible /v1/chat/completions.
 */
class LlamaClient
{
    private const SYSTEM_PROMPT = <<<'PROMPT'
Anda adalah analis risiko keamanan informasi untuk pemerintah daerah di Indonesia.
Anda menerima satu temuan teknis dalam format JSON yang dihasilkan scanner.
Tugas Anda menjelaskan temuan tersebut untuk Risk Register dalam bahasa Indonesia formal dan ringkas.

Aturan:
- Gunakan hanya informasi dari JSON input. Jangan menambah temuan, nomor CVE, versi software, nama produk, atau URL yang tidak ada di input.
- Jawaban dipakai ulang untuk website lain dengan temuan yang sama, jadi tulis secara umum: jangan menyebut nama website, host, URL, nama file, nama cookie, atau nomor versi software.
- Jangan menyatakan website aman atau tidak aman secara keseluruhan.
- Setiap nilai berupa 1 sampai 2 kalimat.
- Jawab HANYA dengan satu objek JSON dengan kunci berikut:
  "finding" (nama temuan yang mudah dipahami),
  "threat" (ancaman),
  "vulnerability" (kerawanan),
  "category" (kategori risiko),
  "impact_description" (kemungkinan dampak),
  "recommendation" (rencana aksi penanganan),
  "additional_control" (kontrol tambahan).
PROMPT;

    /**
     * @param  array<string, mixed>  $input
     * @return array<string, mixed>
     *
     * @throws ConnectionException jika layanan AI tidak dapat dihubungi atau timeout
     * @throws RuntimeException jika respons tidak valid
     */
    public function analyze(array $input): array
    {
        $response = Http::timeout((int) config('siprika.ai.timeout'))
            ->connectTimeout(5)
            ->acceptJson()
            ->post(rtrim((string) config('siprika.ai.url'), '/').'/v1/chat/completions', [
                'model' => config('siprika.ai.model'),
                'temperature' => 0.2,
                'max_tokens' => 800,
                'response_format' => ['type' => 'json_object'],
                'messages' => [
                    ['role' => 'system', 'content' => self::SYSTEM_PROMPT],
                    ['role' => 'user', 'content' => json_encode($input, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT)],
                ],
            ]);

        if (! $response->successful()) {
            throw new RuntimeException("Layanan AI merespons status {$response->status()}.");
        }

        $content = (string) $response->json('choices.0.message.content', '');
        $content = trim(preg_replace('/^```(?:json)?|```$/m', '', trim($content)));
        $decoded = json_decode($content, true);

        if (! is_array($decoded)) {
            throw new RuntimeException('Output AI bukan JSON yang valid.');
        }

        return $decoded;
    }
}
