<?php

namespace App\Models;

use App\Ai\LlamaClient;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;

#[Fillable(['finding_key', 'finding', 'threat', 'vulnerability', 'category', 'impact_description', 'recommendation', 'additional_control', 'model'])]
class AiAnalysis extends Model
{
    /**
     * Model AI dan versi prompt yang membuat hasil ini, contoh "qwen2.5-7b-instruct.Q4_K_M.gguf | prompt 2".
     */
    public static function currentTag(): string
    {
        return config('siprika.ai.model').' | prompt '.LlamaClient::PROMPT_VERSION;
    }

    /**
     * Hanya hasil dari model dan versi prompt saat ini; hasil lama dibuat ulang saat pemeriksaan berikutnya
     * dan sementara itu kolom deskriptif memakai teks katalog.
     *
     * @param  Builder<self>  $query
     */
    public function scopeCurrent(Builder $query): void
    {
        $query->where('model', self::currentTag());
    }
}
