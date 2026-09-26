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
        Schema::table('scan_targets', function (Blueprint $table) {
            // Ringkasan hasil untuk tab Overview (URL final, IP, title, server, TLS, teknologi)
            $table->json('overview')->nullable()->after('status');
            // Progress per tahap pemeriksaan (bagian 13)
            $table->json('progress')->nullable()->after('overview');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('scan_targets', function (Blueprint $table) {
            $table->dropColumn(['overview', 'progress']);
        });
    }
};
