@props(['target', 'inline' => false])
@use('App\Enums\ScanTargetStatus')
@use('App\Support\Duration')

{{-- Waktu pemeriksaan satu website: mulai, lama berjalan (diperbarui tiap detik oleh resources/js/app.js),
     perkiraan sisa (diperbarui lewat polling progress), atau jam selesai dan durasi setelah selesai. --}}
@php
    $running = $target->status === ScanTargetStatus::Running;
    $elapsed = $target->elapsedSeconds();
    // Website yang dibatalkan sebelum mulai punya jam selesai tanpa jam mulai
    $finishedFormat = $target->started_at && $target->finished_at?->isSameDay($target->started_at) ? 'H:i:s' : 'd-m-Y H:i:s';
    $item = $inline ? '' : 'block';
@endphp

<span {{ $attributes->class([$inline ? 'inline-flex flex-wrap items-center gap-x-1.5 gap-y-0.5' : 'block space-y-0.5']) }}
      data-scan-time="{{ $target->id }}" @if ($running) data-running @endif>
    @if ($target->started_at === null)
        <span class="{{ $item }}">{{ $target->status === ScanTargetStatus::Queued ? 'Menunggu antrean' : 'Tidak dijalankan' }}</span>
    @else
        <span class="{{ $item }}">Mulai {{ $target->started_at->format('d-m-Y H:i:s') }}</span>
        @if ($running)
            @if ($inline)<span aria-hidden="true">&middot;</span>@endif
            <span class="{{ $item }}">Berjalan <span data-elapsed="{{ $elapsed }}" class="font-medium text-slate-700 tabular-nums">{{ Duration::format($elapsed) }}</span></span>
            @if ($inline)<span aria-hidden="true">&middot;</span>@endif
            <span class="{{ $item }}">Perkiraan sisa <span data-remaining class="tabular-nums">{{ Duration::approximate($target->remainingSeconds()) }}</span></span>
        @elseif ($target->finished_at)
            @if ($inline)<span aria-hidden="true">&middot;</span>@endif
            <span class="{{ $item }}">Selesai {{ $target->finished_at->format($finishedFormat) }}</span>
            @if ($inline)<span aria-hidden="true">&middot;</span>@endif
            <span class="{{ $item }}">Durasi <span class="font-medium text-slate-700">{{ Duration::format($elapsed) }}</span></span>
        @endif
    @endif
</span>
