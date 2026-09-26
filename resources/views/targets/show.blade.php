@extends('layouts.app')

@section('title', $target->host.' - SIPRIKA')

@if (! $target->status->isFinished())
    @push('head')
        {{-- Cadangan jika JavaScript mati; progress biasanya diperbarui resources/js/app.js --}}
        <noscript><meta http-equiv="refresh" content="5"></noscript>
    @endpush
@endif

@section('content')
    <div class="rounded-lg border border-slate-200 bg-white p-6 shadow-sm">
        <div class="flex flex-wrap items-start justify-between gap-4">
            <div>
                <p class="text-xs text-slate-500">
                    <a href="{{ route('scans.show', $target->batch) }}" class="hover:underline">Batch #{{ $target->batch->id }}</a>
                    &middot; Mode {{ $target->batch->mode->label() }}
                </p>
                <h1 class="mt-1 font-mono text-lg font-semibold break-all text-slate-900">{{ $target->url }}</h1>
            </div>
            <div class="flex flex-wrap items-center gap-2">
                <x-badge :class="$target->status->badgeClass()">{{ $target->status->label() }}</x-badge>
                @if ($target->status->hasResult())
                    <a href="{{ route('targets.export', $target) }}" class="rounded-md bg-emerald-700 px-4 py-2 text-sm font-semibold text-white hover:bg-emerald-800">Export Excel</a>
                @endif
            </div>
        </div>

        @if ($target->error_message)
            <p class="mt-3 rounded-md bg-red-50 px-3 py-2 text-sm text-red-800">{{ $target->error_message }}</p>
        @endif

        @if (! $target->status->isFinished())
            <div class="mt-4" data-progress-url="{{ route('scans.progress', $target->batch) }}">
                <x-progress-bar :target="$target" />
                @if ($target->progress)
                    <div class="mt-4">
                        @include('partials.progress', ['progress' => $target->progress])
                    </div>
                @endif
            </div>
        @endif
    </div>

    <nav class="mt-6 flex flex-wrap gap-1 border-b border-slate-200">
        @foreach ($tabs as $key => $label)
            <a href="{{ route('targets.show', ['scanTarget' => $target, 'tab' => $key]) }}"
               class="rounded-t-md px-4 py-2 text-sm font-medium {{ $tab === $key ? 'border border-b-white border-slate-200 bg-white text-slate-900 -mb-px' : 'text-slate-500 hover:text-slate-800' }}">
                {{ $label }}
                @if ($key === 'findings')
                    <span class="text-xs text-slate-400">({{ $target->findings->count() }})</span>
                @elseif ($key === 'risk')
                    <span class="text-xs text-slate-400">({{ $target->riskItems->count() }})</span>
                @endif
            </a>
        @endforeach
    </nav>

    <div class="rounded-b-lg border border-t-0 border-slate-200 bg-white p-6 shadow-sm">
        @include("targets.tabs.{$tab}")
    </div>
@endsection
