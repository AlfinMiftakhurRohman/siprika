@props(['label', 'value', 'icon' => null, 'tone' => 'slate', 'note' => null])

{{-- Kartu angka ringkasan, contoh: <x-stat label="Website" :value="3" icon="globe" tone="sky" /> --}}
@php
    $tones = [
        'slate' => 'bg-slate-100 text-slate-600',
        'sky' => 'bg-sky-100 text-sky-700',
        'emerald' => 'bg-emerald-100 text-emerald-700',
        'amber' => 'bg-amber-100 text-amber-700',
        'red' => 'bg-red-100 text-red-700',
        'indigo' => 'bg-indigo-100 text-indigo-700',
    ];
@endphp

<div {{ $attributes->merge(['class' => 'flex items-center gap-4 rounded-xl border border-slate-200 bg-white p-4 shadow-sm']) }}>
    @if ($icon)
        <span class="grid size-11 shrink-0 place-items-center rounded-lg {{ $tones[$tone] ?? $tones['slate'] }}">
            <x-icon :name="$icon" class="size-6" />
        </span>
    @endif
    <div class="min-w-0">
        <p class="text-2xl leading-tight font-semibold text-slate-900 tabular-nums">{{ $value }}</p>
        <p class="text-sm text-slate-500">{{ $label }}</p>
        @if ($note)
            <p class="mt-0.5 text-xs text-slate-400">{{ $note }}</p>
        @endif
    </div>
</div>
