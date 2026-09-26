@use('App\Scanner\ScanProgress')

<ul class="grid grid-cols-1 gap-x-6 gap-y-1 text-sm sm:grid-cols-2">
    @foreach ($progress ?? [] as $step)
        <li class="flex justify-between gap-3 border-b border-slate-100 py-1">
            <span>{{ $step['label'] }}</span>
            <span class="{{ ScanProgress::cssClass($step['status']) }}">{{ ScanProgress::label($step['status']) }}</span>
        </li>
    @endforeach
</ul>
