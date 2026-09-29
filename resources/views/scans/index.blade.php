@extends('layouts.app')

@section('title', 'Riwayat Pemeriksaan - SIPRIKA')

@section('content')
    <div class="mb-6">
        <h1 class="text-2xl font-semibold tracking-tight text-slate-900">Riwayat Pemeriksaan</h1>
        <p class="mt-1 text-sm text-slate-500">
            {{ $batches->total() }} batch tersimpan. Centang riwayat yang ingin dihapus beserta hasil pemeriksaan dan Risk Register-nya.
        </p>
    </div>

    @if ($errors->any())
        <div class="mb-4 flex gap-3 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
            <x-icon name="warning" class="mt-0.5 size-5 text-red-600" />
            <span>{{ $errors->first() }}</span>
        </div>
    @endif

    @if ($batches->isEmpty())
        <div class="rounded-2xl border border-dashed border-slate-300 bg-white px-6 py-12 text-center">
            <x-icon name="clock" class="mx-auto size-8 text-slate-300" />
            <p class="mt-3 text-sm text-slate-600">Belum ada riwayat pemeriksaan.</p>
            <a href="{{ route('scans.create') }}" class="mt-2 inline-block text-sm font-medium text-blue-700 hover:underline">Mulai pemeriksaan</a>
        </div>
    @else
        <form method="POST" action="{{ route('scans.destroy') }}" data-bulk-form data-bulk-total="{{ $deletableCount }}"
              data-confirm="Hapus {count} riwayat pemeriksaan beserta hasil dan Risk Register-nya? Tindakan ini tidak dapat dibatalkan.">
            @csrf
            @method('DELETE')
            <input type="hidden" name="all" value="0">

            <div class="mb-3 flex flex-wrap items-center justify-between gap-3">
                <div class="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-slate-600">
                    <span data-bulk-count>Belum ada yang dipilih</span>
                    <button type="button" data-bulk-everything hidden class="font-medium text-blue-700 hover:underline">
                        Pilih semua {{ $deletableCount }} riwayat
                    </button>
                </div>
                <button type="submit" data-bulk-submit class="inline-flex items-center gap-2 rounded-xl bg-red-600 px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-red-700 focus:ring-4 focus:ring-red-200 focus:outline-none disabled:cursor-not-allowed disabled:opacity-40">
                    <x-icon name="trash" class="size-4" /> Hapus yang dipilih
                </button>
            </div>

            @include('scans.partials.history-table', ['batches' => $batches, 'selectable' => true])
        </form>

        {{ $batches->links('partials.pagination') }}

        <p class="mt-4 text-xs text-slate-500">
            Batch yang masih berjalan tidak dapat dipilih. Riwayat yang dihapus tidak dapat dikembalikan; hasil AI yang tersimpan per jenis temuan tetap dipakai ulang.
        </p>
    @endif
@endsection
