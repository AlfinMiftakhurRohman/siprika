<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Residual Risk (bagian 24.6). Nullable supaya baris lama tetap valid sampai dihitung ulang
     * dengan php artisan siprika:recalculate.
     */
    public function up(): void
    {
        Schema::table('risk_register_items', function (Blueprint $table) {
            $table->unsignedTinyInteger('residual_impact')->nullable()->after('risk_status');
            $table->unsignedTinyInteger('residual_likelihood')->nullable()->after('residual_impact');
            $table->unsignedTinyInteger('residual_risk')->nullable()->after('residual_likelihood');
            // Acceptable / Not Acceptable, sama seperti rumus kolom Y template
            $table->string('residual_status', 20)->nullable()->after('residual_risk');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('risk_register_items', function (Blueprint $table) {
            $table->dropColumn(['residual_impact', 'residual_likelihood', 'residual_risk', 'residual_status']);
        });
    }
};
