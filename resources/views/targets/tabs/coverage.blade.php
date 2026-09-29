@use('App\Enums\ScanMode')
@use('App\Support\SourceLabel')

<p class="mb-4 text-sm text-slate-600">
    Daftar semua pemeriksaan beserta statusnya. NOT ASSESSED berarti pemeriksaan tidak dilakukan atau tidak dapat dilakukan oleh tool yang tersedia, bukan berarti aman.
    Pemeriksaan hanya dilakukan pada halaman utama dan beberapa path umum, tanpa login.
</p>

@if ($target->batch->mode === ScanMode::Quick)
    <p class="mb-4 rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-800">
        Mode Cepat: hanya halaman utama yang diperiksa, exposure dibatasi pada path umum, Nuclei memakai profil ringan tanpa template CVE,
        serta TLS lengkap (testssl.sh), Port/Web Service (Nmap), WhatWeb, dan OWASP ZAP tidak dijalankan. Gunakan Mode Standar untuk pemeriksaan lengkap.
    </p>
@endif

@if ($catalogCoverage !== [])
    <h3 class="mb-2 font-semibold text-slate-900">Kunci Katalog</h3>
    <p class="mb-3 text-sm text-slate-600">
        Status setiap jenis temuan yang dinilai SIPRIKA (bagian 23.1). PASS berarti sudah diperiksa dan tidak ditemukan masalah.
        NOT ASSESSED dan ERROR berarti belum diperiksa, sehingga tidak boleh dianggap aman.
    </p>

    <div class="mb-8 overflow-x-auto">
    <table class="w-full min-w-2xl text-left text-sm">
        <thead class="border-b border-slate-200 text-xs tracking-wide text-slate-500 uppercase">
            <tr>
                <th class="py-2 pr-4 font-medium">Kunci</th>
                <th class="w-36 py-2 pr-4 font-medium">Status</th>
                <th class="w-48 py-2 pr-4 font-medium">Pemeriksa</th>
                <th class="py-2 font-medium">Keterangan</th>
            </tr>
        </thead>
        <tbody class="divide-y divide-slate-100">
            @foreach ($catalogCoverage as $row)
                <tr class="align-top" data-catalog-key="{{ $row['key'] }}">
                    <td class="py-2 pr-4">
                        {{ $row['title'] }}
                        <code class="block text-xs text-slate-400">{{ $row['key'] }}</code>
                    </td>
                    <td class="py-2 pr-4">
                        <x-badge :class="$row['status']->badgeClass()">{{ $row['status']->value }}</x-badge>
                    </td>
                    <td class="py-2 pr-4 text-slate-500">{{ $row['assessors'] === [] ? '-' : implode(', ', $row['assessors']) }}</td>
                    <td class="py-2 wrap-break-word text-slate-700">{{ $row['note'] }}</td>
                </tr>
            @endforeach
        </tbody>
    </table>
    </div>

    <h3 class="mb-2 font-semibold text-slate-900">Daftar Pemeriksaan</h3>
@endif

<div class="overflow-x-auto">
<table class="w-full min-w-2xl text-left text-sm">
    <thead class="border-b border-slate-200 text-xs tracking-wide text-slate-500 uppercase">
        <tr>
            <th class="w-48 py-2 pr-4 font-medium">Pemeriksaan</th>
            <th class="w-36 py-2 pr-4 font-medium">Tool</th>
            <th class="w-36 py-2 pr-4 font-medium">Status</th>
            <th class="py-2 font-medium">Keterangan</th>
        </tr>
    </thead>
    <tbody class="divide-y divide-slate-100">
        @foreach ($target->observations as $observation)
            <tr class="align-top">
                <td class="py-2 pr-4">{{ $observation->label }}</td>
                <td class="py-2 pr-4 text-slate-500">{{ SourceLabel::of($observation->tool) }}</td>
                <td class="py-2 pr-4">
                    <x-badge :class="$observation->status->badgeClass()">{{ $observation->status->value }}</x-badge>
                </td>
                <td class="py-2 wrap-break-word text-slate-700">{{ $observation->summary }}</td>
            </tr>
        @endforeach
    </tbody>
</table>
</div>
