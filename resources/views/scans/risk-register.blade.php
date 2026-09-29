@extends('layouts.app')

@section('title', 'Risk Register Batch #'.$batch->id.' - SIPRIKA')

{{-- Sheet Risk Register lebar (27 kolom), halaman memakai lebar penuh --}}
@section('main_width', 'max-w-none')

@section('content')
    <div class="flex flex-wrap items-end justify-between gap-3">
        <div>
            <a href="{{ route('scans.show', $batch) }}" class="inline-flex items-center gap-1 text-xs font-medium text-slate-500 hover:text-slate-700">
                <x-icon name="arrow-left" class="size-3.5" /> Batch #{{ $batch->id }} &middot; Mode {{ $batch->mode->label() }}
            </a>
            <h1 class="mt-1 text-2xl font-semibold tracking-tight text-slate-900">Risk Register</h1>
            <p class="mt-1 text-sm text-slate-500">{{ $items->count() }} risiko dari {{ $items->pluck('scan_target_id')->unique()->count() }} website</p>
        </div>
        <a href="{{ route('scans.export', $batch) }}" class="inline-flex items-center gap-2 rounded-xl bg-emerald-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-emerald-700">
            <x-icon name="download" class="size-4" /> Export ke Excel (template)
        </a>
    </div>

    <div class="mt-4">
        @include('partials.risk-register-sheet', ['items' => $items])
    </div>
@endsection
