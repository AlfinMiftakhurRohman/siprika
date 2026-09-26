<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('scan_observations', function (Blueprint $table) {
            $table->id();
            $table->foreignId('scan_target_id')->constrained()->cascadeOnDelete();
            $table->string('check_key', 64);
            $table->string('label');
            $table->string('tool', 32);
            // PASS, FAIL, INFO, ERROR, N/A, NOT ASSESSED
            $table->string('status', 20);
            $table->text('summary')->nullable();
            // Nilai mentah yang menjadi dasar keputusan (bagian 22.6)
            $table->json('raw')->nullable();
            $table->unsignedInteger('duration_ms')->nullable();
            $table->timestamps();

            $table->index(['scan_target_id', 'check_key']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('scan_observations');
    }
};
