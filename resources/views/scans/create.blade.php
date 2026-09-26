@extends('layouts.app')

@section('title', 'Pemeriksaan Baru - SIPRIKA')

@section('content')
    <form method="POST" action="{{ route('scans.store') }}" class="space-y-6 rounded-lg border border-slate-200 bg-white p-6 shadow-sm">
        @csrf

        @if ($errors->any())
            <div class="rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
                <p class="font-medium">Input belum dapat diproses:</p>
                <ul class="mt-2 list-disc space-y-1 pl-5">
                    @foreach ($errors->all() as $error)
                        <li class="break-all">{{ $error }}</li>
                    @endforeach
                </ul>
            </div>
        @endif

        <div>
            <label for="urls" class="block text-sm font-semibold text-slate-900">Target Website</label>
            <p class="mt-1 text-sm text-slate-500">
                Satu website per baris, contoh esakip.jemberkab.go.id atau https://esakip.jemberkab.go.id. Tanpa http:// atau https:// dianggap https://.
                @if ($allowsAllDomains)
                    Pastikan Anda berwenang memeriksa website tersebut.
                @else
                    Domain yang diizinkan: {{ implode(', ', config('siprika.allowed_domains')) }} beserta subdomainnya.
                @endif
            </p>
            <textarea
                id="urls"
                name="urls"
                rows="8"
                required
                placeholder="esakip.jemberkab.go.id&#10;https://website-b.jemberkab.go.id"
                class="mt-2 w-full rounded-md border border-slate-300 px-3 py-2 font-mono text-sm focus:border-sky-500 focus:ring-2 focus:ring-sky-200 focus:outline-none"
            >{{ old('urls') }}</textarea>
        </div>

        <fieldset>
            <legend class="text-sm font-semibold text-slate-900">Mode Pemeriksaan</legend>
            <div class="mt-2 space-y-3">
                @foreach ($modes as $mode)
                    <label class="flex cursor-pointer items-start gap-3 rounded-md border border-slate-200 px-4 py-3 hover:bg-slate-50 has-checked:border-sky-500 has-checked:bg-sky-50">
                        <input type="radio" name="mode" value="{{ $mode->value }}" class="mt-1" @checked(old('mode', $defaultMode->value) === $mode->value)>
                        <span>
                            <span class="block text-sm font-medium text-slate-900">{{ $mode->label() }}</span>
                            <span class="mt-0.5 block text-sm text-slate-600">{{ $mode->description() }}</span>
                        </span>
                    </label>
                @endforeach
            </div>
        </fieldset>

        <button type="submit" class="rounded-md bg-sky-700 px-5 py-2.5 text-sm font-semibold tracking-wide text-white hover:bg-sky-800">
            MULAI PEMERIKSAAN
        </button>
    </form>

    @if ($recentBatches->isNotEmpty())
        <section class="mt-8">
            <h2 class="text-sm font-semibold text-slate-900">Pemeriksaan Terakhir</h2>
            <div class="mt-3 overflow-x-auto rounded-lg border border-slate-200 bg-white shadow-sm">
                <table class="w-full text-left text-sm">
                    <thead class="border-b border-slate-200 bg-slate-50 text-slate-600">
                        <tr>
                            <th class="px-4 py-2 font-medium">Batch</th>
                            <th class="px-4 py-2 font-medium">Mode</th>
                            <th class="px-4 py-2 font-medium">Dibuat</th>
                            <th class="px-4 py-2 font-medium">Jumlah Target</th>
                            <th class="px-4 py-2"></th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-slate-100">
                        @foreach ($recentBatches as $recent)
                            <tr>
                                <td class="px-4 py-2">#{{ $recent->id }}</td>
                                <td class="px-4 py-2">{{ $recent->mode->label() }}</td>
                                <td class="px-4 py-2">{{ $recent->created_at->format('d-m-Y H:i') }}</td>
                                <td class="px-4 py-2">{{ $recent->targets_count }}</td>
                                <td class="px-4 py-2 text-right">
                                    <a href="{{ route('scans.show', $recent) }}" class="font-medium text-sky-700 hover:underline">Lihat</a>
                                </td>
                            </tr>
                        @endforeach
                    </tbody>
                </table>
            </div>
        </section>
    @endif
@endsection
