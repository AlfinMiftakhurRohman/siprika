<?php

use App\Http\Controllers\ScanController;
use App\Http\Controllers\ScanTargetController;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Route;
use Illuminate\View\Middleware\ShareErrorsFromSession;

Route::get('/', [ScanController::class, 'create'])->name('scans.create');
Route::get('/scans', [ScanController::class, 'index'])->name('scans.index');
Route::post('/scans', [ScanController::class, 'store'])->name('scans.store');
Route::delete('/scans', [ScanController::class, 'destroy'])->name('scans.destroy');
Route::get('/scans/{scanBatch}', [ScanController::class, 'show'])->name('scans.show');
// Dipanggil setiap 2 detik selama pemeriksaan: tanpa session supaya tidak menulis database setiap kali
Route::get('/scans/{scanBatch}/progress', [ScanController::class, 'progress'])
    ->withoutMiddleware([StartSession::class, ShareErrorsFromSession::class, PreventRequestForgery::class])
    ->name('scans.progress');
Route::get('/scans/{scanBatch}/risk-register', [ScanController::class, 'riskRegister'])->name('scans.risk-register');
Route::post('/scans/{scanBatch}/cancel', [ScanController::class, 'cancel'])->name('scans.cancel');
Route::post('/scans/{scanBatch}/rescan', [ScanController::class, 'rescan'])->name('scans.rescan');
Route::get('/scans/{scanBatch}/export', [ScanController::class, 'export'])->name('scans.export');
Route::get('/scans/{scanBatch}/raw-report', [ScanController::class, 'rawReport'])->name('scans.raw-report');

Route::get('/targets/{scanTarget}', [ScanTargetController::class, 'show'])->name('targets.show');
Route::get('/targets/{scanTarget}/export', [ScanTargetController::class, 'export'])->name('targets.export');
Route::get('/targets/{scanTarget}/raw-report', [ScanTargetController::class, 'rawReport'])->name('targets.raw-report');
Route::post('/targets/{scanTarget}/rescan', [ScanTargetController::class, 'rescan'])->name('targets.rescan');
