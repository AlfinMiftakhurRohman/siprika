<?php

namespace Database\Factories;

use App\Enums\ScanMode;
use App\Models\ScanBatch;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<ScanBatch>
 */
class ScanBatchFactory extends Factory
{
    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'mode' => ScanMode::Standard,
        ];
    }
}
