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
    <body class="min-h-screen bg-slate-50 text-slate-800 antialiased">
        <header class="border-b border-slate-200 bg-white">
            <div class="mx-auto flex max-w-6xl flex-wrap items-baseline justify-between gap-3 px-4 py-4">
                <div class="flex items-baseline gap-3">
                    <a href="{{ route('scans.create') }}" class="text-xl font-semibold tracking-tight text-slate-900">SIPRIKA</a>
                    <span class="text-sm text-slate-500">Sistem Penilaian Risiko Keamanan Aplikasi</span>
                </div>
                <a href="{{ route('scans.create') }}" class="text-sm font-medium text-sky-700 hover:underline">Pemeriksaan Baru</a>
            </div>
        </header>

        <main class="mx-auto @yield('main_width', 'max-w-6xl') px-4 py-8">
            @if (session('status'))
                <div class="mb-6 rounded-md border border-sky-200 bg-sky-50 px-4 py-3 text-sm text-sky-800">
                    {{ session('status') }}
                </div>
            @endif

            @if (session('error'))
                <div class="mb-6 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
                    {{ session('error') }}
                </div>
            @endif

            @yield('content')
        </main>

        <footer class="mx-auto max-w-6xl px-4 pb-8 text-xs text-slate-400">
            SIPRIKA hanya melakukan pemeriksaan non-eksploitatif. Tidak ditemukannya kerawanan tidak berarti website sepenuhnya aman.
        </footer>
    </body>
</html>
