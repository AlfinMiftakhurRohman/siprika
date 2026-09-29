{{-- Tabel riwayat batch. $selectable menambah kotak centang untuk menghapus beberapa riwayat sekaligus. --}}
@php($selectable ??= false)
<div class="overflow-x-auto rounded-2xl border border-slate-200 bg-white shadow-sm">
    <table class="w-full text-left text-sm">
        <thead class="border-b border-slate-200 bg-slate-50 text-xs tracking-wide text-slate-500 uppercase">
            <tr>
                @if ($selectable)
                    <th class="w-10 py-3 pr-1 pl-4">
                        <input type="checkbox" data-bulk-all aria-label="Pilih semua riwayat di halaman ini" class="size-4 cursor-pointer accent-blue-600">
                    </th>
                @endif
                <th class="px-4 py-3 font-medium">Batch</th>
                <th class="px-4 py-3 font-medium">Website</th>
                <th class="hidden px-4 py-3 font-medium sm:table-cell">Mode</th>
                <th class="hidden px-4 py-3 font-medium md:table-cell">Dibuat</th>
                <th class="hidden px-4 py-3 font-medium sm:table-cell">Status</th>
                <th class="px-4 py-3"></th>
            </tr>
        </thead>
        <tbody class="divide-y divide-slate-100">
            @foreach ($batches as $batch)
                @php($statusBadges = $batch->targets->groupBy(fn ($target) => $target->status->value))
                <tr class="align-top transition hover:bg-slate-50">
                    @if ($selectable)
                        <td class="py-3 pr-1 pl-4">
                            @if ($batch->isRunning())
                                <input type="checkbox" disabled title="Masih berjalan, tidak dapat dihapus" aria-label="Batch #{{ $batch->id }} masih berjalan" class="size-4 cursor-not-allowed opacity-40">
                            @else
                                <input type="checkbox" name="batches[]" value="{{ $batch->id }}" data-bulk-item aria-label="Pilih Batch #{{ $batch->id }}" class="size-4 cursor-pointer accent-blue-600">
                            @endif
                        </td>
                    @endif
                    <td class="px-4 py-3 font-medium whitespace-nowrap text-slate-900">#{{ $batch->id }}</td>
                    <td class="px-4 py-3 break-all">
                        {{ $batch->targets->take(2)->pluck('host')->implode(', ') }}
                        @if ($batch->targets->count() > 2)
                            <span class="text-slate-500">dan {{ $batch->targets->count() - 2 }} lainnya</span>
                        @endif
                        {{-- Di layar kecil status tampil di bawah nama website --}}
                        <div class="mt-1 flex flex-wrap gap-1 sm:hidden">
                            @foreach ($statusBadges as $group)
                                <x-badge :class="$group->first()->status->badgeClass()">{{ $group->count() }} {{ $group->first()->status->label() }}</x-badge>
                            @endforeach
                        </div>
                    </td>
                    <td class="hidden px-4 py-3 sm:table-cell">
                        <span class="inline-flex items-center gap-1 text-slate-600">
                            <x-icon :name="$batch->mode->value === 'quick' ? 'bolt' : 'shield-check'" class="size-4 text-slate-400" />
                            {{ $batch->mode->label() }}
                        </span>
                    </td>
                    <td class="hidden px-4 py-3 whitespace-nowrap text-slate-600 md:table-cell">{{ $batch->created_at->format('d-m-Y H:i') }}</td>
                    <td class="hidden px-4 py-3 sm:table-cell">
                        <div class="flex flex-wrap gap-1">
                            {{-- Jumlah website per status, contoh "2 Selesai" dan "1 Gagal" --}}
                            @foreach ($statusBadges as $group)
                                <x-badge :class="$group->first()->status->badgeClass()">{{ $group->count() }} {{ $group->first()->status->label() }}</x-badge>
                            @endforeach
                        </div>
                    </td>
                    <td class="px-4 py-3 text-right whitespace-nowrap">
                        <a href="{{ route('scans.show', $batch) }}" class="inline-flex items-center gap-1 font-medium text-blue-700 hover:underline">
                            Lihat
                        </a>
                    </td>
                </tr>
            @endforeach
        </tbody>
    </table>
</div>
