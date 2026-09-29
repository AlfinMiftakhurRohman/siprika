{{-- Navigasi halaman sederhana berbahasa Indonesia, dipakai lewat $paginator->links('partials.pagination') --}}
@if ($paginator->hasPages())
    <nav class="mt-4 flex flex-wrap items-center justify-between gap-3 text-sm" aria-label="Navigasi halaman">
        <span class="text-slate-500">Halaman {{ $paginator->currentPage() }} dari {{ $paginator->lastPage() }}</span>
        <div class="flex gap-2">
            @if ($paginator->onFirstPage())
                <span class="rounded-lg border border-slate-200 px-3 py-1.5 text-slate-300">Sebelumnya</span>
            @else
                <a href="{{ $paginator->previousPageUrl() }}" rel="prev" class="rounded-lg border border-slate-300 bg-white px-3 py-1.5 font-medium text-slate-700 shadow-sm hover:bg-slate-50">Sebelumnya</a>
            @endif

            @if ($paginator->hasMorePages())
                <a href="{{ $paginator->nextPageUrl() }}" rel="next" class="rounded-lg border border-slate-300 bg-white px-3 py-1.5 font-medium text-slate-700 shadow-sm hover:bg-slate-50">Berikutnya</a>
            @else
                <span class="rounded-lg border border-slate-200 px-3 py-1.5 text-slate-300">Berikutnya</span>
            @endif
        </div>
    </nav>
@endif
