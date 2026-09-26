@forelse ($target->findings->sortByDesc(fn ($finding) => $finding->severity->rank()) as $finding)
    <article class="border-b border-slate-100 py-4 first:pt-0 last:border-0">
        <div class="flex flex-wrap items-center gap-2">
            <x-badge :class="$finding->severity->badgeClass()">{{ $finding->severity->label() }}</x-badge>
            <h3 class="font-semibold text-slate-900">{{ $finding->title }}</h3>
            <code class="text-xs text-slate-400">{{ $finding->finding_key }}</code>
        </div>

        @if ($finding->description)
            <p class="mt-2 text-sm text-slate-700">{{ $finding->description }}</p>
        @endif

        <dl class="mt-2 grid grid-cols-1 gap-x-6 gap-y-1 text-sm sm:grid-cols-3">
            <div><dt class="inline text-slate-500">Scanner:</dt> <dd class="inline">{{ implode(', ', $finding->sources) }}</dd></div>
            @if ($finding->cve)
                <div><dt class="inline text-slate-500">CVE:</dt> <dd class="inline">{{ $finding->cve }}</dd></div>
            @endif
            @if ($finding->cvss)
                <div><dt class="inline text-slate-500">CVSS:</dt> <dd class="inline">{{ $finding->cvss }}</dd></div>
            @endif
        </dl>

        @if ($finding->recommendation)
            <p class="mt-2 text-sm"><span class="text-slate-500">Rekomendasi:</span> {{ $finding->recommendation }}</p>
        @endif

        <div class="mt-3 rounded-md bg-slate-50 p-3">
            <p class="text-xs font-semibold text-slate-600">Evidence</p>
            <ul class="mt-1 space-y-1 text-xs text-slate-700">
                @foreach ($finding->evidences as $evidence)
                    <li class="break-all">
                        <span class="font-medium">[{{ $evidence->source }}]</span>
                        {{ $evidence->detail }}
                        @if ($evidence->endpoint)
                            <span class="text-slate-500">&middot; {{ $evidence->endpoint }}</span>
                        @endif
                        @if (! empty($evidence->raw['snippet']))
                            <code class="mt-1 block rounded bg-white px-2 py-1 text-slate-600">{{ $evidence->raw['snippet'] }}</code>
                        @endif
                    </li>
                @endforeach
            </ul>
        </div>
    </article>
@empty
    <p class="text-sm text-slate-500">
        {{ $target->status->isFinished() ? 'Tidak ada finding. Tidak ditemukannya kerawanan tidak berarti website sepenuhnya aman.' : 'Finding akan muncul setelah pemeriksaan selesai.' }}
    </p>
@endforelse
