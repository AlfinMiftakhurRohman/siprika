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
        // Hasil AI disimpan per kunci finding dan dipakai ulang (bagian 27)
        Schema::create('ai_analyses', function (Blueprint $table) {
            $table->id();
            $table->string('finding_key', 191)->unique();
            $table->string('finding')->nullable();
            $table->text('threat')->nullable();
            $table->text('vulnerability')->nullable();
            $table->string('category')->nullable();
            $table->text('impact_description');
            $table->text('recommendation');
            $table->text('additional_control');
            $table->string('model')->nullable();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('ai_analyses');
    }
};
