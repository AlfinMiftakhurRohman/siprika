<?php

use App\Http\Controllers\ScanController;
use App\Http\Controllers\ScanTargetController;
use Illuminate\Support\Facades\Route;

Route::get('/', [ScanController::class, 'create'])->name('scans.create');
Route::post('/scans', [ScanController::class, 'store'])->name('scans.store');
Route::get('/scans/{scanBatch}', [ScanController::class, 'show'])->name('scans.show');
Route::get('/scans/{scanBatch}/progress', [ScanController::class, 'progress'])->name('scans.progress');
Route::get('/scans/{scanBatch}/risk-register', [ScanController::class, 'riskRegister'])->name('scans.risk-register');
Route::post('/scans/{scanBatch}/cancel', [ScanController::class, 'cancel'])->name('scans.cancel');
Route::get('/scans/{scanBatch}/export', [ScanController::class, 'export'])->name('scans.export');

Route::get('/targets/{scanTarget}', [ScanTargetController::class, 'show'])->name('targets.show');
Route::get('/targets/{scanTarget}/export', [ScanTargetController::class, 'export'])->name('targets.export');
