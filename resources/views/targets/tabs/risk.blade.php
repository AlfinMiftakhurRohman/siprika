@if ($target->riskItems->isNotEmpty())
    <p class="mb-3 text-sm text-slate-600">
        Tampilan mengikuti sheet Perangkat Lunak pada template Risk Register.
        <a href="{{ route('scans.risk-register', $target->batch) }}" class="font-medium text-sky-700 hover:underline">Buka Risk Register seluruh batch (layar penuh)</a>
    </p>
@endif

@include('partials.risk-register-sheet', ['items' => $target->riskItems])
