@extends('layouts.app')

@use('App\Enums\ScanTargetStatus')

@section('title', 'Antrean Pemeriksaan #'.$batch->id.' - SIPRIKA')

@if ($running)
    @push('head')
        {{-- Cadangan jika JavaScript mati; progress biasanya diperbarui resources/js/app.js --}}
        <noscript><meta http-equiv="refresh" content="5"></noscript>
    @endpush
@endif

@php
    $finished = $batch->targets->filter(fn ($target) => $target->status->hasResult())->count();
    $inQueue = $batch->targets->filter(fn ($target) => ! $target->status->isFinished())->count();
    $failed = $batch->targets->filter(fn ($target) => in_array($target->status, [ScanTargetStatus::Failed, ScanTargetStatus::Cancelled], true))->count();
@endphp

@section('content')
    <div class="flex flex-wrap items-start justify-between gap-4">
        <div>
            <a href="{{ route('scans.index') }}" class="inline-flex items-center gap-1 text-xs font-medium text-slate-500 hover:text-slate-700">
                <x-icon name="arrow-left" class="size-3.5" /> Riwayat
            </a>
            <h1 class="mt-1 text-2xl font-semibold tracking-tight text-slate-900">Antrean Pemeriksaan #{{ $batch->id }}</h1>
            <p class="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-slate-500">
                <span class="inline-flex items-center gap-1">
                    <x-icon :name="$batch->mode->value === 'quick' ? 'bolt' : 'shield-check'" class="size-4" />
                    Mode {{ $batch->mode->label() }}
                </span>
                <span class="inline-flex items-center gap-1"><x-icon name="clock" class="size-4" /> {{ $batch->created_at->format('d-m-Y H:i:s') }}</span>
            </p>
        </div>

        <div class="flex flex-wrap gap-2">
            @if ($hasResults)
                <a href="{{ route('scans.risk-register', $batch) }}" class="inline-flex items-center gap-2 rounded-xl border border-slate-300 bg-white px-4 py-2 text-sm font-semibold text-slate-700 shadow-sm hover:bg-slate-50">
                    <x-icon name="chart" class="size-4" /> Lihat Risk Register
                </a>
                <a href="{{ route('scans.export', $batch) }}" class="inline-flex items-center gap-2 rounded-xl bg-emerald-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-emerald-700">
                    <x-icon name="download" class="size-4" /> Export Risk Register (Excel)
                </a>
            @endif

            @if ($batch->targets->contains(fn ($t) => $t->status->hasStarted()))
                <a href="{{ route('scans.raw-report', $batch) }}" class="inline-flex items-center gap-2 rounded-xl border border-slate-300 bg-white px-4 py-2 text-sm font-semibold text-slate-700 shadow-sm hover:bg-slate-50"
                   title="Semua pemeriksaan, temuan, teknologi, dan hasil tool dalam file Excel terpisah dari template Risk Register">
                    <x-icon name="document" class="size-4" /> Laporan Mentah (Excel)
                </a>
            @endif

            @unless ($running)
                <form method="POST" action="{{ route('scans.rescan', $batch) }}">
                    @csrf
                    <button type="submit" class="inline-flex items-center gap-2 rounded-xl border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-700 shadow-sm hover:bg-slate-50"
                            title="Memeriksa ulang semua website dengan mode yang sama sebagai batch baru">
                        <x-icon name="refresh" class="size-4" /> Pindai Ulang
                    </button>
                </form>
            @endunless

            @if ($batch->targets->contains(fn ($t) => $t->status === ScanTargetStatus::Queued))
                <form method="POST" action="{{ route('scans.cancel', $batch) }}">
                    @csrf
                    <button type="submit" class="inline-flex items-center gap-2 rounded-xl border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-700 shadow-sm hover:bg-slate-50">
                        <x-icon name="x-mark" class="size-4" /> Batalkan yang Menunggu
                    </button>
                </form>
            @endif
        </div>
    </div>

    <div class="mt-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <x-stat label="Website" :value="$batch->targets->count()" icon="globe" tone="sky" />
        <x-stat label="Selesai diperiksa" :value="$finished" icon="check-circle" tone="emerald" :note="$failed > 0 ? $failed.' gagal atau dibatalkan' : null" />
        <x-stat label="Berjalan / menunggu" :value="$inQueue" icon="queue" :tone="$inQueue > 0 ? 'indigo' : 'slate'" />
        <x-stat label="Risiko" :value="$riskCount" icon="warning" :tone="$notAcceptableCount > 0 ? 'red' : 'amber'" :note="$notAcceptableCount.' Not Acceptable'" />
    </div>

    @if ($running)
        <p class="mt-4 flex items-center gap-2 text-xs text-slate-500">
            <span class="relative flex size-2"><span class="absolute inline-flex size-full animate-ping rounded-full bg-sky-400 opacity-75"></span><span class="relative inline-flex size-2 rounded-full bg-sky-500"></span></span>
            Progress diperbarui otomatis. Pastikan SIPRIKA dijalankan dengan php artisan siprika:serve supaya antrean diproses.
        </p>
    @endif

    <div class="mt-4 overflow-x-auto rounded-2xl border border-slate-200 bg-white shadow-sm" @if ($running) data-progress-url="{{ route('scans.progress', $batch) }}" @endif>
        <table class="w-full text-left text-sm">
            <thead class="border-b border-slate-200 bg-slate-50 text-xs tracking-wide text-slate-500 uppercase">
                <tr>
                    <th class="w-12 px-4 py-3 font-medium">No</th>
                    <th class="px-4 py-3 font-medium">URL dan Progress</th>
                    <th class="hidden w-40 px-4 py-3 font-medium sm:table-cell">Status</th>
                    <th class="hidden w-56 px-4 py-3 font-medium md:table-cell">Waktu</th>
                    <th class="w-28 px-4 py-3"></th>
                </tr>
            </thead>
            <tbody class="divide-y divide-slate-100">
                @foreach ($batch->targets as $target)
                    <tr class="align-top">
                        <td class="px-4 py-4 text-slate-500">{{ $target->position }}</td>
                        <td class="px-4 py-4">
                            <span class="block font-mono font-medium break-all text-slate-900">{{ $target->url }}</span>
                            {{-- Di layar kecil status tampil di bawah URL --}}
                            <x-badge :class="$target->status->badgeClass().' mt-1 sm:hidden'">{{ $target->status->label() }}</x-badge>
                            <x-progress-bar :target="$target" class="mt-3 max-w-xl" />
                            {{-- Di layar kecil kolom Waktu disembunyikan, waktunya tampil di bawah progress --}}
                            <x-scan-time :target="$target" inline class="mt-2 text-xs text-slate-500 md:hidden" />
                            @if ($target->error_message)
                                <p class="mt-2 flex items-start gap-1.5 text-xs text-red-700"><x-icon name="warning" class="size-4" /> {{ $target->error_message }}</p>
                            @endif
                            @if ($target->status === ScanTargetStatus::Running)
                                <details class="mt-2">
                                    <summary class="cursor-pointer text-xs font-medium text-blue-700">Lihat semua tahap</summary>
                                    <div class="mt-2">
                                        @include('partials.progress', ['progress' => $target->progress])
                                    </div>
                                </details>
                            @endif
                        </td>
                        <td class="hidden px-4 py-4 sm:table-cell">
                            <x-badge :class="$target->status->badgeClass()">{{ $target->status->label() }}</x-badge>
                        </td>
                        <td class="hidden px-4 py-4 text-xs text-slate-500 md:table-cell">
                            <x-scan-time :target="$target" />
                        </td>
                        <td class="px-4 py-4 text-right whitespace-nowrap">
                            @if ($target->status->hasStarted())
                                <a href="{{ route('targets.show', $target) }}" class="inline-flex items-center gap-1 font-medium text-blue-700 hover:underline">
                                    <x-icon name="eye" class="size-4" /> Lihat Hasil
                                </a>
                            @endif
                        </td>
                    </tr>
                @endforeach
            </tbody>
        </table>
    </div>
@endsection
