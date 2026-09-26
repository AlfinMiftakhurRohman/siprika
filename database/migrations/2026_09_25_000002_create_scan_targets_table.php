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
        Schema::create('scan_targets', function (Blueprint $table) {
            $table->id();
            $table->foreignId('scan_batch_id')->constrained()->cascadeOnDelete();
            // Urutan antrean di dalam batch, dimulai dari 1
            $table->unsignedInteger('position');
            $table->string('url', 2048);
            $table->string('host')->index();
            $table->string('status', 20)->default('QUEUED')->index();
            // Diisi oleh scanner pada tahap berikutnya
            $table->timestamp('started_at')->nullable();
            $table->timestamp('finished_at')->nullable();
            $table->text('error_message')->nullable();
            $table->timestamps();

            $table->unique(['scan_batch_id', 'position']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('scan_targets');
    }
};
