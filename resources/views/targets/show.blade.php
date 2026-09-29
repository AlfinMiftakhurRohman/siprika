@extends('layouts.app')

@use('App\Enums\ObservationStatus')
@use('App\Models\RiskRegisterItem')

@section('title', $target->host.' - SIPRIKA')

@if (! $target->status->isFinished())
    @push('head')
        {{-- Cadangan jika JavaScript mati; progress biasanya diperbarui resources/js/app.js --}}
        <noscript><meta http-equiv="refresh" content="5"></noscript>
    @endpush
@endif

@php
    $tabIcons = ['overview' => 'globe', 'security' => 'shield-check', 'findings' => 'search', 'risk' => 'chart', 'coverage' => 'list'];
    $levelCounts = $target->riskItems->countBy('risk_level');
    $notAcceptable = $target->riskItems->filter->isNotAcceptable()->count();
    $coverageCounts = collect($catalogCoverage)->countBy(fn ($row) => $row['status']->value);
    $assessedCount = collect($catalogCoverage)->reject(fn ($row) => in_array($row['status'], [ObservationStatus::NotAssessed, ObservationStatus::Error], true))->count();
@endphp

@section('content')
    <div class="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
        <div class="flex flex-wrap items-start justify-between gap-4">
            <div class="min-w-0">
                <a href="{{ route('scans.show', $target->batch) }}" class="inline-flex items-center gap-1 text-xs font-medium text-slate-500 hover:text-slate-700">
                    <x-icon name="arrow-left" class="size-3.5" /> Batch #{{ $target->batch->id }} &middot; Mode {{ $target->batch->mode->label() }}
                </a>
                <div class="mt-2 flex flex-wrap items-center gap-3">
                    <span class="grid size-10 shrink-0 place-items-center rounded-xl bg-sky-100 text-sky-700">
                        <x-icon name="globe" class="size-6" />
                    </span>
                    <h1 class="font-mono text-lg font-semibold break-all text-slate-900 sm:text-xl">{{ $target->url }}</h1>
                    <x-badge :class="$target->status->badgeClass()">{{ $target->status->label() }}</x-badge>
                </div>
                <p class="mt-2 flex items-start gap-1 text-xs text-slate-500">
                    <x-icon name="clock" class="size-4" />
                    <x-scan-time :target="$target" inline />
                </p>
            </div>
            <div class="flex flex-wrap items-center gap-2">
                @if ($target->status->hasResult())
                    <a href="{{ route('targets.export', $target) }}" class="inline-flex items-center gap-2 rounded-xl bg-emerald-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-emerald-700">
                        <x-icon name="download" class="size-4" /> Export Risk Register (Excel)
                    </a>
                @endif
                @if ($target->status->hasStarted())
                    <a href="{{ route('targets.raw-report', $target) }}" class="inline-flex items-center gap-2 rounded-xl border border-slate-300 bg-white px-4 py-2 text-sm font-semibold text-slate-700 shadow-sm hover:bg-slate-50"
                       title="Semua pemeriksaan, temuan, teknologi, dan hasil tool dalam file Excel terpisah dari template Risk Register">
                        <x-icon name="document" class="size-4" /> Laporan Mentah (Excel)
                    </a>
                @endif
                @if ($target->status->isFinished())
                    <form method="POST" action="{{ route('targets.rescan', $target) }}">
                        @csrf
                        <button type="submit" class="inline-flex items-center gap-2 rounded-xl border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-700 shadow-sm hover:bg-slate-50"
                                title="Memeriksa ulang website ini dengan mode yang sama sebagai batch baru">
                            <x-icon name="refresh" class="size-4" /> Pindai Ulang
                        </button>
                    </form>
                @endif
            </div>
        </div>

        @if ($target->error_message)
            <p class="mt-4 flex items-start gap-2 rounded-xl bg-red-50 px-4 py-3 text-sm text-red-800">
                <x-icon name="warning" class="mt-0.5 size-5 text-red-600" /> {{ $target->error_message }}
            </p>
        @endif

        @if (! $target->status->isFinished())
            <div class="mt-5" data-progress-url="{{ route('scans.progress', $target->batch) }}">
                <x-progress-bar :target="$target" />
                @if ($target->progress)
                    <div class="mt-4">
                        @include('partials.progress', ['progress' => $target->progress])
                    </div>
                @endif
            </div>
        @endif
    </div>

    @if ($target->status->isFinished() && $catalogCoverage !== [])
        {{-- Ringkasan: jumlah risiko per level dan cakupan pemeriksaan --}}
        <div class="mt-4 grid gap-4 lg:grid-cols-3">
            <div class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm lg:col-span-2">
                <div class="flex items-baseline justify-between gap-3">
                    <h2 class="text-sm font-semibold text-slate-900">Risiko</h2>
                    <span class="text-xs text-slate-500">{{ $target->riskItems->count() }} baris Risk Register &middot; {{ $notAcceptable }} Not Acceptable</span>
                </div>
                <div class="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-5">
                    @foreach (RiskRegisterItem::LEVELS as $level => $colors)
                        <div class="rounded-xl border border-slate-100 bg-slate-50 px-3 py-2">
                            <p class="flex items-center gap-1.5 text-xs text-slate-500">
                                <span class="size-2 rounded-full {{ $colors['dot'] }}"></span>{{ $level }}
                            </p>
                            <p class="mt-1 text-xl font-semibold text-slate-900 tabular-nums">{{ $levelCounts[$level] ?? 0 }}</p>
                        </div>
                    @endforeach
                </div>
            </div>

            <div class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
                <div class="flex items-baseline justify-between gap-3">
                    <h2 class="text-sm font-semibold text-slate-900">Cakupan Pemeriksaan</h2>
                    <span class="text-xs text-slate-500">{{ $assessedCount }}/{{ count($catalogCoverage) }} dinilai</span>
                </div>
                <div class="mt-4 flex h-3 overflow-hidden rounded-full bg-slate-100" role="img" aria-label="Status {{ count($catalogCoverage) }} jenis temuan">
                    @foreach ([ObservationStatus::Fail, ObservationStatus::Pass, ObservationStatus::NotApplicable, ObservationStatus::Error, ObservationStatus::NotAssessed] as $status)
                        @if (($coverageCounts[$status->value] ?? 0) > 0)
                            <div class="{{ $status->barClass() }}" style="width: {{ $coverageCounts[$status->value] / count($catalogCoverage) * 100 }}%"></div>
                        @endif
                    @endforeach
                </div>
                <div class="mt-3 flex flex-wrap gap-x-3 gap-y-1 text-xs text-slate-600">
                    @foreach ($coverageCounts as $status => $count)
                        <span class="inline-flex items-center gap-1.5"><span class="size-2 rounded-full {{ ObservationStatus::from($status)->barClass() }}"></span>{{ $count }} {{ $status }}</span>
                    @endforeach
                </div>
            </div>
        </div>
    @endif

    <nav class="mt-6 flex gap-1 overflow-x-auto rounded-xl border border-slate-200 bg-white p-1 shadow-sm" aria-label="Bagian hasil">
        @foreach ($tabs as $key => $label)
            <a href="{{ route('targets.show', ['scanTarget' => $target, 'tab' => $key]) }}"
               @class(['flex shrink-0 items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium whitespace-nowrap transition',
                   'bg-navy-900 text-white shadow-sm' => $tab === $key,
                   'text-slate-600 hover:bg-slate-100 hover:text-slate-900' => $tab !== $key])
               @if ($tab === $key) aria-current="page" @endif>
                <x-icon :name="$tabIcons[$key] ?? 'info'" class="size-4" />
                {{ $label }}
                @if ($key === 'findings')
                    {{-- Hasil informasi Nuclei tidak dihitung, tampil terpisah di tab Findings --}}
                    <span data-tab-count @class(['rounded-full px-1.5 text-xs', 'bg-white/20' => $tab === $key, 'bg-slate-100 text-slate-500' => $tab !== $key])>{{ $target->findings->reject->isInformational()->count() }}</span>
                @elseif ($key === 'risk')
                    <span data-tab-count @class(['rounded-full px-1.5 text-xs', 'bg-white/20' => $tab === $key, 'bg-slate-100 text-slate-500' => $tab !== $key])>{{ $target->riskItems->count() }}</span>
                @endif
            </a>
        @endforeach
    </nav>

    <div class="mt-4 rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
        @include("targets.tabs.{$tab}")
    </div>
@endsection
