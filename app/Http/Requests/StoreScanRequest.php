<?php

namespace App\Http\Requests;

use App\Enums\ScanMode;
use App\Support\TargetUrlNormalizer;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Str;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Validator;
use InvalidArgumentException;

class StoreScanRequest extends FormRequest
{
    /**
     * Target hasil normalisasi, tanpa duplikat, sesuai urutan input.
     *
     * @var list<array{url: string, host: string}>
     */
    private array $targets = [];

    private int $duplicateCount = 0;

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            'urls' => ['required', 'string'],
            'mode' => ['required', Rule::enum(ScanMode::class)],
        ];
    }

    /**
     * @return array<string, string>
     */
    public function messages(): array
    {
        return [
            'urls.required' => 'Masukkan minimal satu URL target.',
            'urls.string' => 'Daftar URL tidak valid.',
            'mode.required' => 'Pilih mode pemeriksaan.',
            'mode.enum' => 'Mode pemeriksaan tidak valid, pilih Cepat atau Standar.',
        ];
    }

    public function mode(): ScanMode
    {
        return $this->enum('mode', ScanMode::class);
    }

    /**
     * Validasi per baris URL setelah aturan dasar lolos.
     *
     * @return array<int, callable>
     */
    public function after(): array
    {
        return [
            function (Validator $validator) {
                if ($validator->errors()->has('urls')) {
                    return;
                }

                $this->validateUrlLines($validator);
            },
        ];
    }

    /**
     * @return list<array{url: string, host: string}>
     */
    public function targets(): array
    {
        return $this->targets;
    }

    public function duplicateCount(): int
    {
        return $this->duplicateCount;
    }

    private function validateUrlLines(Validator $validator): void
    {
        $normalizer = TargetUrlNormalizer::fromConfig();
        $targets = [];
        $duplicates = 0;

        foreach (preg_split('/\R/', (string) $this->input('urls')) as $index => $line) {
            $line = trim($line);

            if ($line === '') {
                continue;
            }

            try {
                $target = $normalizer->normalize($line);
            } catch (InvalidArgumentException $e) {
                $lineNumber = $index + 1;
                $validator->errors()->add('urls', "Baris {$lineNumber} ({$this->shorten($line)}): {$e->getMessage()}");

                continue;
            }

            if (isset($targets[$target['url']])) {
                $duplicates++;

                continue;
            }

            $targets[$target['url']] = $target;
        }

        if ($validator->errors()->has('urls')) {
            return;
        }

        $max = (int) config('siprika.max_urls_per_batch', 100);

        if (count($targets) > $max) {
            $validator->errors()->add('urls', "Maksimal {$max} URL per pemeriksaan, input berisi ".count($targets).' URL.');

            return;
        }

        $this->targets = array_values($targets);
        $this->duplicateCount = $duplicates;
    }

    private function shorten(string $line): string
    {
        return Str::limit($line, 100);
    }
}
