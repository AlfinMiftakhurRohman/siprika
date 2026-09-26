@use('App\Enums\ScanMode')

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

<table class="w-full text-left text-sm">
    <thead class="border-b border-slate-200 text-slate-600">
        <tr>
            <th class="py-2 pr-4 font-medium">Pemeriksaan</th>
            <th class="w-24 py-2 pr-4 font-medium">Tool</th>
            <th class="w-36 py-2 pr-4 font-medium">Status</th>
            <th class="py-2 font-medium">Keterangan</th>
        </tr>
    </thead>
    <tbody class="divide-y divide-slate-100">
        @foreach ($target->observations as $observation)
            <tr class="align-top">
                <td class="py-2 pr-4">{{ $observation->label }}</td>
                <td class="py-2 pr-4 text-slate-500">{{ $observation->tool }}</td>
                <td class="py-2 pr-4">
                    <x-badge :class="$observation->status->badgeClass()">{{ $observation->status->value }}</x-badge>
                </td>
                <td class="py-2 wrap-break-word text-slate-700">{{ $observation->summary }}</td>
            </tr>
        @endforeach
    </tbody>
</table>
