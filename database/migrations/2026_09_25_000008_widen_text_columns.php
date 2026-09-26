<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Kolom teks yang bisa melebihi 255 karakter. SQLite tidak membatasi panjang, tetapi
     * PostgreSQL dan MySQL menolak insert sehingga target yang sudah selesai diperiksa jadi FAILED.
     */
    public function up(): void
    {
        // Output AI divalidasi sampai 1000 karakter per kunci
        Schema::table('ai_analyses', function (Blueprint $table) {
            $table->text('finding')->nullable()->change();
            $table->text('category')->nullable()->change();
        });

        // Nama aset berisi title website (maksimal 120 karakter) ditambah nama host (maksimal 253 karakter)
        Schema::table('risk_register_items', function (Blueprint $table) {
            $table->text('asset')->change();
        });

        // Nama template Nuclei tidak dibatasi panjangnya
        Schema::table('scan_findings', function (Blueprint $table) {
            $table->text('title')->change();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('ai_analyses', function (Blueprint $table) {
            $table->string('finding')->nullable()->change();
            $table->string('category')->nullable()->change();
        });

        Schema::table('risk_register_items', function (Blueprint $table) {
            $table->string('asset')->change();
        });

        Schema::table('scan_findings', function (Blueprint $table) {
            $table->string('title')->change();
        });
    }
};
