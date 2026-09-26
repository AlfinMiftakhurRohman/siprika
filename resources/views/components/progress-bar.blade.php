@props(['target'])

{{-- Loading bar satu website. Angka dan bar diperbarui resources/js/app.js lewat atribut data-* --}}
<div {{ $attributes }} data-target-progress="{{ $target->id }}" data-status="{{ $target->status->value }}">
    <div class="flex items-center justify-between gap-3 text-xs">
        <span data-step class="text-slate-600">{{ $target->currentStep() ?? $target->status->label() }}</span>
        <span data-percent class="font-semibold text-slate-800 tabular-nums">{{ $target->progressPercent() }}%</span>
    </div>
    <div class="mt-1 h-2 overflow-hidden rounded-full bg-slate-100" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="{{ $target->progressPercent() }}">
        <div data-bar class="h-2 rounded-full transition-all duration-700 {{ $target->status->barClass() }}" style="width: {{ $target->progressPercent() }}%"></div>
    </div>
</div>
