<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * SQLite dan PostgreSQL tidak membuat index untuk foreign key secara otomatis. Tanpa index, memuat bukti
     * setiap temuan dan menghapus temuan membaca seluruh tabel, yang makin lambat seiring bertambahnya hasil pemeriksaan.
     */
    public function up(): void
    {
        Schema::table('finding_evidences', function (Blueprint $table) {
            $table->index('scan_finding_id');
        });

        Schema::table('risk_register_items', function (Blueprint $table) {
            $table->index('scan_finding_id');
        });
    }

    public function down(): void
    {
        Schema::table('finding_evidences', function (Blueprint $table) {
            $table->dropIndex(['scan_finding_id']);
        });

        Schema::table('risk_register_items', function (Blueprint $table) {
            $table->dropIndex(['scan_finding_id']);
        });
    }
};
