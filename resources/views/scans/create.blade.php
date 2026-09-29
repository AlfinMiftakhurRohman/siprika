@extends('layouts.app')

@section('title', 'Pemeriksaan Baru - SIPRIKA')

@section('content')
    <div class="mb-6">
        <h1 class="text-2xl font-semibold tracking-tight text-slate-900">Pemeriksaan Baru</h1>
        <p class="mt-1 text-sm text-slate-500">Periksa keamanan dasar website secara non-eksploitatif, lalu susun Risk Register sesuai template.</p>
    </div>

    <div class="grid gap-6 lg:grid-cols-3">
        <form method="POST" action="{{ route('scans.store') }}" class="space-y-6 rounded-2xl border border-slate-200 bg-white p-6 shadow-sm lg:col-span-2">
            @csrf

            @if ($errors->any())
                <div class="flex gap-3 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
                    <x-icon name="warning" class="mt-0.5 size-5 text-red-600" />
                    <div>
                        <p class="font-medium">Input belum dapat diproses:</p>
                        <ul class="mt-2 list-disc space-y-1 pl-5">
                            @foreach ($errors->all() as $error)
                                <li class="break-all">{{ $error }}</li>
                            @endforeach
                        </ul>
                    </div>
                </div>
            @endif

            <div>
                <div class="flex items-end justify-between gap-3">
                    <label for="urls" class="block text-sm font-semibold text-slate-900">Target Website</label>
                    <span class="text-xs text-slate-500" data-url-count-for="urls"></span>
                </div>
                <p class="mt-1 text-sm text-slate-500">
                    Satu website per baris, contoh e-sakip.jemberkab.go.id atau https://e-sakip.jemberkab.go.id. Tanpa http:// atau https:// dianggap https://.
                    @if ($allowsAllDomains)
                        Pastikan Anda berwenang memeriksa website tersebut.
                    @else
                        Domain yang diizinkan: {{ implode(', ', config('siprika.allowed_domains')) }} beserta subdomainnya.
                    @endif
                </p>
                <textarea
                    id="urls"
                    name="urls"
                    rows="7"
                    required
                    placeholder="e-sakip.jemberkab.go.id&#10;https://website-b.jemberkab.go.id"
                    class="mt-3 w-full rounded-xl border border-slate-300 bg-slate-50 px-4 py-3 font-mono text-sm transition focus:border-sky-500 focus:bg-white focus:ring-4 focus:ring-sky-100 focus:outline-none"
                >{{ old('urls') }}</textarea>
            </div>

            <fieldset>
                <legend class="text-sm font-semibold text-slate-900">Mode Pemeriksaan</legend>
                <div class="mt-3 grid gap-3 sm:grid-cols-2">
                    @foreach ($modes as $mode)
                        <label class="flex cursor-pointer flex-col rounded-xl border border-slate-200 p-4 transition hover:border-sky-300 hover:bg-sky-50/40 has-checked:border-sky-500 has-checked:bg-sky-50 has-checked:ring-4 has-checked:ring-sky-100">
                            <input type="radio" name="mode" value="{{ $mode->value }}" class="sr-only" @checked(old('mode', $defaultMode->value) === $mode->value)>
                            <span class="flex items-center justify-between gap-2">
                                <span class="flex items-center gap-2">
                                    <span class="grid size-8 place-items-center rounded-lg {{ $mode->value === 'quick' ? 'bg-amber-100 text-amber-700' : 'bg-indigo-100 text-indigo-700' }}">
                                        <x-icon :name="$mode->value === 'quick' ? 'bolt' : 'shield-check'" class="size-5" />
                                    </span>
                                    <span class="font-semibold text-slate-900">{{ $mode->label() }}</span>
                                </span>
                                <span class="rounded-full bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-600">
                                    ± {{ $mode->value === 'quick' ? '2' : '8' }} menit/website
                                </span>
                            </span>
                            <span class="mt-2 text-sm text-slate-600">{{ $mode->description() }}</span>
                        </label>
                    @endforeach
                </div>
            </fieldset>

            <div class="flex flex-wrap items-center gap-3">
                <button type="submit" class="inline-flex items-center gap-2 rounded-xl bg-blue-600 px-6 py-3 text-sm font-semibold tracking-wide text-white shadow-md shadow-blue-600/25 transition hover:bg-blue-700 focus:ring-4 focus:ring-blue-200 focus:outline-none">
                    <x-icon name="play" class="size-4" />
                    MULAI PEMERIKSAAN
                </button>
                <span class="text-xs text-slate-500">Website diperiksa satu per satu sesuai urutan.</span>
            </div>
        </form>

        <aside class="space-y-4">
            <div class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
                <h2 class="text-sm font-semibold text-slate-900">Yang diperiksa</h2>
                <ul class="mt-3 space-y-3 text-sm text-slate-600">
                    @foreach ([
                        ['lock', 'HTTPS, sertifikat, dan protokol TLS'],
                        ['shield-check', 'Security headers dan atribut cookie'],
                        ['document', 'File sensitif dan directory listing'],
                        ['search', 'Nuclei, testssl.sh, WhatWeb, Nmap, dan OWASP ZAP (Standar)'],
                        ['chart', 'Risk Register otomatis sesuai template, dibantu AI lokal'],
                    ] as [$icon, $text])
                        <li class="flex gap-3">
                            <x-icon :name="$icon" class="mt-0.5 size-5 text-sky-600" />
                            <span>{{ $text }}</span>
                        </li>
                    @endforeach
                </ul>
            </div>
            <div class="rounded-2xl border border-amber-200 bg-amber-50 p-5 text-sm text-amber-900">
                <p class="flex items-center gap-2 font-semibold"><x-icon name="warning" class="size-5 text-amber-600" /> Non-eksploitatif</p>
                <p class="mt-2">Tanpa brute force, eksploitasi, atau login. Jaga laptop tetap menyala selama pemeriksaan Mode Standar.</p>
            </div>
        </aside>
    </div>

    @if ($recentBatches->isNotEmpty())
        <section id="riwayat" class="mt-10 scroll-mt-6">
            <div class="flex flex-wrap items-center justify-between gap-2">
                <h2 class="flex items-center gap-2 text-base font-semibold text-slate-900">
                    <x-icon name="clock" class="size-5 text-slate-400" />
                    Pemeriksaan Terakhir
                </h2>
                <a href="{{ route('scans.index') }}" class="text-sm font-medium text-blue-700 hover:underline">Lihat semua &amp; hapus riwayat</a>
            </div>
            <div class="mt-3">
                @include('scans.partials.history-table', ['batches' => $recentBatches])
            </div>
        </section>
    @endif
@endsection
