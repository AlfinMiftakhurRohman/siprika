<!DOCTYPE html>
<html lang="id">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        @stack('head')

        <title>@yield('title', 'SIPRIKA')</title>

        @if (file_exists(public_path('build/manifest.json')) || file_exists(public_path('hot')))
            @fonts
            @vite(['resources/css/app.css', 'resources/js/app.js'])
        @endif
    </head>
    <body class="flex min-h-screen flex-col bg-slate-100 text-slate-800 antialiased">
        <header class="bg-navy-900 text-white shadow-sm">
            <div class="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-3 px-4 py-3">
                <a href="{{ route('scans.create') }}" class="flex items-center gap-3">
                    <span class="grid size-10 place-items-center rounded-xl bg-linear-to-br from-sky-400 to-blue-600 shadow-md shadow-blue-900/40">
                        <x-icon name="shield-check" class="size-6 text-white" />
                    </span>
                    <span>
                        <span class="block text-lg leading-tight font-semibold tracking-tight">SIPRIKA</span>
                        <span class="block text-xs text-slate-300">Sistem Penilaian Risiko Keamanan Aplikasi</span>
                    </span>
                </a>

                <nav class="flex items-center gap-1 text-sm font-medium">
                    <a href="{{ route('scans.create') }}"
                       @class(['flex items-center gap-1.5 rounded-lg px-3 py-2 transition',
                           'bg-white/15 text-white' => request()->routeIs('scans.create'),
                           'text-slate-300 hover:bg-white/10 hover:text-white' => ! request()->routeIs('scans.create')])>
                        <x-icon name="search" class="size-4" />
                        Pemeriksaan Baru
                    </a>
                    <a href="{{ route('scans.index') }}"
                       @class(['flex items-center gap-1.5 rounded-lg px-3 py-2 transition',
                           'bg-white/15 text-white' => request()->routeIs('scans.index'),
                           'text-slate-300 hover:bg-white/10 hover:text-white' => ! request()->routeIs('scans.index')])>
                        <x-icon name="clock" class="size-4" />
                        Riwayat
                    </a>
                </nav>
            </div>
        </header>

        <main class="mx-auto w-full @yield('main_width', 'max-w-6xl') flex-1 px-4 py-8">
            @if (session('status'))
                <div class="mb-6 flex items-start gap-3 rounded-xl border border-sky-200 bg-sky-50 px-4 py-3 text-sm text-sky-900">
                    <x-icon name="info" class="mt-0.5 size-5 text-sky-600" />
                    <span>{{ session('status') }}</span>
                </div>
            @endif

            @if (session('error'))
                <div class="mb-6 flex items-start gap-3 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
                    <x-icon name="warning" class="mt-0.5 size-5 text-red-600" />
                    <span>{{ session('error') }}</span>
                </div>
            @endif

            @yield('content')
        </main>

        <footer class="border-t border-slate-200 bg-white">
            <div class="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-2 px-4 py-4 text-xs text-slate-500">
                <span class="flex items-center gap-1.5">
                    <x-icon name="lock" class="size-4 text-slate-400" />
                    SIPRIKA hanya melakukan pemeriksaan non-eksploitatif. Tidak ditemukannya kerawanan tidak berarti website sepenuhnya aman.
                </span>
                <span>Diskominfo Kabupaten Jember</span>
            </div>
        </footer>
    </body>
</html>
