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
        Schema::create('risk_register_items', function (Blueprint $table) {
            $table->id();
            $table->foreignId('scan_target_id')->constrained()->cascadeOnDelete();
            $table->foreignId('scan_finding_id')->constrained()->cascadeOnDelete();
            $table->string('finding_key', 191);
            $table->string('asset');
            $table->string('threat');
            $table->text('vulnerability');
            $table->string('category');
            $table->text('impact_description');
            $table->string('impact_area');
            $table->unsignedTinyInteger('impact');
            $table->unsignedTinyInteger('likelihood');
            $table->unsignedTinyInteger('inherent_risk');
            $table->string('risk_level', 20);
            // Acceptable / Not Acceptable
            $table->string('risk_status', 20);
            $table->unsignedSmallInteger('priority');
            $table->text('action_plan');
            $table->text('output');
            $table->text('additional_control');
            // catalog atau ai: asal teks kolom Dampak, Rencana Aksi, dan Kontrol Tambahan
            $table->string('text_source', 10);
            $table->timestamps();

            $table->unique(['scan_target_id', 'finding_key']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('risk_register_items');
    }
};
