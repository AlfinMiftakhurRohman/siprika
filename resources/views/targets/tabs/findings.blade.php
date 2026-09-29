@use('App\Scanner\CatalogCoverage')

@php
    $unassessed = CatalogCoverage::unassessedCount($catalogCoverage);
    // Hasil Nuclei berseverity info di luar katalog dikelompokkan terpisah supaya kerawanan tidak tenggelam
    [$informational, $findings] = $target->findings
        ->sortByDesc(fn ($finding) => $finding->severity->rank())
        ->partition(fn ($finding) => $finding->isInformational());
@endphp

@if ($unassessed > 0)
    {{-- Bagian 22.10: halaman hasil tidak boleh menyiratkan website aman untuk kunci yang tidak diperiksa --}}
    <p class="mb-4 rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-800">
        {{ $unassessed }} dari {{ count($catalogCoverage) }} jenis temuan tidak diperiksa atau pemeriksaannya gagal (NOT ASSESSED/ERROR), sehingga tidak dapat dinyatakan aman.
        Lihat tab <a href="{{ route('targets.show', ['scanTarget' => $target, 'tab' => 'coverage']) }}" class="underline">Coverage</a>.
    </p>
@endif

@forelse ($findings as $finding)
    @include('targets.partials.finding')
@empty
    <p class="text-sm text-slate-500">
        {{ $target->status->isFinished() ? 'Tidak ada finding. Tidak ditemukannya kerawanan tidak berarti website sepenuhnya aman.' : 'Finding akan muncul setelah pemeriksaan selesai.' }}
    </p>
@endforelse

@if ($informational->isNotEmpty())
    <details class="mt-6 rounded-md border border-slate-200">
        <summary class="cursor-pointer px-4 py-3 text-sm font-medium text-slate-700">
            Informasi dari scanner ({{ $informational->count() }}), tidak masuk Risk Register
        </summary>
        <div class="border-t border-slate-100 px-4 pt-4">
            @foreach ($informational as $finding)
                @include('targets.partials.finding')
            @endforeach
        </div>
    </details>
@endif
