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
    /**
     * Naik setiap kali aturan prompt berubah, supaya hasil AI tersimpan dari prompt lama dibuat ulang (AiAnalysis::current).
     * Versi 2: teks acuan katalog ikut dikirim, karena tanpa acuan model 7B sering melebih-lebihkan atau salah
     * menjelaskan dampak (contoh Referrer-Policy disebut dapat "mengarahkan pengguna ke situs lain").
     * Versi 3: aturan untuk temuan yang hanya "terdeteksi" (contoh file .editorconfig disebut memungkinkan perubahan
     * konfigurasi), rekomendasi template Nuclei ikut dikirim, dan jawaban dibatasi schema JSON.
     * Versi 4: rencana aksi untuk file yang dapat diakses publik (versi 3 menyarankan "perbaiki konfigurasi editor").
     * Versi 5: temperature 0, karena pada 0.2 kalimat kadang janggal (contoh "mengalami kerahasiaan informasi").
     */
    public const PROMPT_VERSION = 5;

    private const SYSTEM_PROMPT = <<<'PROMPT'
Anda adalah analis risiko keamanan informasi untuk pemerintah daerah di Indonesia.
Anda menerima satu temuan teknis dalam format JSON yang dihasilkan scanner.
Tugas Anda menjelaskan temuan tersebut untuk Risk Register dalam bahasa Indonesia formal dan ringkas.

Aturan:
- Gunakan hanya informasi dari JSON input. Jangan menambah temuan, nomor CVE, versi software, nama produk, atau URL yang tidak ada di input.
- Input "acuan" berisi dampak, rencana aksi, dan kontrol tambahan yang sudah diperiksa ahli untuk temuan ini. Jawaban harus sejalan dengan acuan: boleh memperjelas atau menyesuaikan dengan judul dan deskripsi temuan, tetapi jangan menambah dampak, akibat, atau jenis serangan yang tidak disebut acuan maupun deskripsi temuan.
- Jangan melebih-lebihkan. Temuan berseverity info atau low berdampak kecil, tulis dampaknya secara proporsional.
- Jika deskripsi temuan hanya menyatakan sesuatu terdeteksi (contoh file tertentu dapat diakses), dampaknya sebatas informasi yang terbuka untuk umum. Jangan menyimpulkan kemampuan mengubah data, mengambil alih sistem, atau mengganggu layanan. Rencana aksinya adalah menghapus file tersebut dari direktori yang dapat diakses publik atau memblokir aksesnya di web server, bukan mengubah isi file.
- Jika ada "rekomendasi_scanner" (bahasa Inggris dari template scanner), jadikan dasar rencana aksi dan tulis ulang dalam bahasa Indonesia.
- Gunakan istilah keamanan yang tepat dan bahasa Indonesia baku.
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
                // 0: jawaban paling konsisten dan dekat dengan teks acuan
                'temperature' => 0,
                'max_tokens' => 800,
                // Schema membuat llama-server selalu mengisi semua kunci (tanpa schema, kunci kadang hilang)
                'response_format' => ['type' => 'json_object', 'schema' => self::schema()],
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

    /**
     * @return array<string, mixed>
     */
    private static function schema(): array
    {
        return [
            'type' => 'object',
            'properties' => array_fill_keys(AiOutputValidator::KEYS, ['type' => 'string', 'minLength' => 1]),
            'required' => AiOutputValidator::KEYS,
            'additionalProperties' => false,
        ];
    }
}
