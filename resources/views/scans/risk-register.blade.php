@extends('layouts.app')

@section('title', 'Risk Register Batch #'.$batch->id.' - SIPRIKA')

{{-- Sheet Risk Register lebar (27 kolom), halaman memakai lebar penuh --}}
@section('main_width', 'max-w-none')

@section('content')
    <div class="flex flex-wrap items-center justify-between gap-3">
        <div>
            <p class="text-xs text-slate-500">
                <a href="{{ route('scans.show', $batch) }}" class="hover:underline">Batch #{{ $batch->id }}</a>
                &middot; Mode {{ $batch->mode->label() }} &middot; {{ $items->count() }} risiko dari {{ $items->pluck('scan_target_id')->unique()->count() }} website
            </p>
            <h1 class="mt-1 text-lg font-semibold text-slate-900">Risk Register</h1>
        </div>
        <a href="{{ route('scans.export', $batch) }}" class="rounded-md bg-emerald-700 px-4 py-2 text-sm font-semibold text-white hover:bg-emerald-800">
            Export ke Excel (template)
        </a>
    </div>

    <div class="mt-4">
        @include('partials.risk-register-sheet', ['items' => $items])
    </div>
@endsection
