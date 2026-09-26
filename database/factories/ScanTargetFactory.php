<?php

namespace Database\Factories;

use App\Enums\ScanTargetStatus;
use App\Models\ScanBatch;
use App\Models\ScanTarget;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<ScanTarget>
 */
class ScanTargetFactory extends Factory
{
    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        $host = fake()->unique()->domainWord().'.jemberkab.go.id';

        return [
            'scan_batch_id' => ScanBatch::factory(),
            'position' => 1,
            'url' => 'https://'.$host,
            'host' => $host,
            'status' => ScanTargetStatus::Queued,
        ];
    }
}
