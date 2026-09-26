@extends('layouts.app')

@use('App\Enums\ScanTargetStatus')

@section('title', 'Antrean Pemeriksaan #'.$batch->id.' - SIPRIKA')

@if ($running)
    @push('head')
        {{-- Cadangan jika JavaScript mati; progress biasanya diperbarui resources/js/app.js --}}
        <noscript><meta http-equiv="refresh" content="5"></noscript>
    @endpush
@endif

@section('content')
    <div class="rounded-lg border border-slate-200 bg-white p-6 shadow-sm">
        <div class="flex flex-wrap items-start justify-between gap-4">
            <h1 class="text-lg font-semibold text-slate-900">Antrean Pemeriksaan #{{ $batch->id }}</h1>

            <div class="flex flex-wrap gap-2">
                @if ($hasResults)
                    <a href="{{ route('scans.risk-register', $batch) }}" class="rounded-md border border-emerald-700 px-4 py-2 text-sm font-semibold text-emerald-800 hover:bg-emerald-50">
                        Lihat Risk Register
                    </a>
                    <a href="{{ route('scans.export', $batch) }}" class="rounded-md bg-emerald-700 px-4 py-2 text-sm font-semibold text-white hover:bg-emerald-800">
                        Export Risk Register (Excel)
                    </a>
                @endif

                @if ($batch->targets->contains(fn ($t) => $t->status === ScanTargetStatus::Queued))
                    <form method="POST" action="{{ route('scans.cancel', $batch) }}">
                        @csrf
                        <button type="submit" class="rounded-md border border-slate-300 px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50">
                            Batalkan yang Menunggu
                        </button>
                    </form>
                @endif
            </div>
        </div>

        <dl class="mt-4 grid grid-cols-1 gap-4 text-sm sm:grid-cols-3">
            <div>
                <dt class="text-slate-500">Mode</dt>
                <dd class="font-medium">{{ $batch->mode->label() }}</dd>
            </div>
            <div>
                <dt class="text-slate-500">Dibuat</dt>
                <dd class="font-medium">{{ $batch->created_at->format('d-m-Y H:i:s') }}</dd>
            </div>
            <div>
                <dt class="text-slate-500">Jumlah Target</dt>
                <dd class="font-medium">{{ $batch->targets->count() }}</dd>
            </div>
        </dl>

        @if ($running)
            <p class="mt-4 text-xs text-slate-500">Progress diperbarui otomatis. Pastikan SIPRIKA dijalankan dengan php artisan siprika:serve supaya antrean diproses.</p>
        @endif
    </div>

    <div class="mt-6 overflow-x-auto rounded-lg border border-slate-200 bg-white shadow-sm" @if ($running) data-progress-url="{{ route('scans.progress', $batch) }}" @endif>
        <table class="w-full text-left text-sm">
            <thead class="border-b border-slate-200 bg-slate-50 text-slate-600">
                <tr>
                    <th class="w-12 px-4 py-3 font-medium">No</th>
                    <th class="px-4 py-3 font-medium">URL dan Progress</th>
                    <th class="w-40 px-4 py-3 font-medium">Status</th>
                    <th class="w-44 px-4 py-3 font-medium">Waktu</th>
                    <th class="w-28 px-4 py-3"></th>
                </tr>
            </thead>
            <tbody class="divide-y divide-slate-100">
                @foreach ($batch->targets as $target)
                    <tr class="align-top">
                        <td class="px-4 py-3 text-slate-500">{{ $target->position }}</td>
                        <td class="px-4 py-3">
                            <span class="font-mono break-all">{{ $target->url }}</span>
                            <x-progress-bar :target="$target" class="mt-2 max-w-xl" />
                            @if ($target->error_message)
                                <p class="mt-1 text-xs text-red-700">{{ $target->error_message }}</p>
                            @endif
                            @if ($target->status === ScanTargetStatus::Running)
                                <details class="mt-2">
                                    <summary class="cursor-pointer text-xs font-medium text-sky-700">Lihat semua tahap</summary>
                                    <div class="mt-2">
                                        @include('partials.progress', ['progress' => $target->progress])
                                    </div>
                                </details>
                            @endif
                        </td>
                        <td class="px-4 py-3">
                            <x-badge :class="$target->status->badgeClass()" data-target-status="{{ $target->id }}">{{ $target->status->label() }}</x-badge>
                        </td>
                        <td class="px-4 py-3 text-xs text-slate-500">
                            @if ($target->started_at)
                                Mulai {{ $target->started_at->format('H:i:s') }}<br>
                            @endif
                            @if ($target->finished_at)
                                Selesai {{ $target->finished_at->format('H:i:s') }}
                            @endif
                        </td>
                        <td class="px-4 py-3 text-right">
                            @if ($target->status->hasStarted())
                                <a href="{{ route('targets.show', $target) }}" class="font-medium text-sky-700 hover:underline">Lihat Hasil</a>
                            @endif
                        </td>
                    </tr>
                @endforeach
            </tbody>
        </table>
    </div>
@endsection
