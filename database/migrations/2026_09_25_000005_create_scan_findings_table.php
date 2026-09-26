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
        Schema::create('scan_findings', function (Blueprint $table) {
            $table->id();
            $table->foreignId('scan_target_id')->constrained()->cascadeOnDelete();
            // Kunci katalog, atau nuclei:<template-id> untuk finding di luar katalog
            $table->string('finding_key', 191);
            $table->string('title');
            $table->text('description')->nullable();
            // info, low, medium, high, critical
            $table->string('severity', 20);
            $table->string('cve', 64)->nullable();
            $table->decimal('cvss', 3, 1)->nullable();
            $table->text('recommendation')->nullable();
            // Daftar scanner yang mendeteksi finding ini
            $table->json('sources');
            $table->timestamps();

            // Deduplikasi: satu finding per website per kunci
            $table->unique(['scan_target_id', 'finding_key']);
        });

        Schema::create('finding_evidences', function (Blueprint $table) {
            $table->id();
            $table->foreignId('scan_finding_id')->constrained()->cascadeOnDelete();
            $table->string('source', 32);
            $table->string('endpoint', 2048)->nullable();
            $table->text('detail');
            $table->json('raw')->nullable();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('finding_evidences');
        Schema::dropIfExists('scan_findings');
    }
};
