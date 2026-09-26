@php
    // Pemeriksaan yang ditampilkan di tab Security Check (bagian 14), sesuai urutan
    $securityChecks = [
        'https', 'http-redirect', 'header-hsts', 'header-csp', 'header-x-frame-options',
        'header-x-content-type-options', 'header-referrer-policy', 'cookie-security',
        'tls-certificate', 'tls-chain', 'tls-expiry', 'tls-protocol', 'testssl',
        'exposure-files', 'directory-listing', 'server-version', 'nuclei',
    ];
@endphp

<table class="w-full text-left text-sm">
    <thead class="border-b border-slate-200 text-slate-600">
        <tr>
            <th class="py-2 pr-4 font-medium">Pemeriksaan</th>
            <th class="w-36 py-2 pr-4 font-medium">Status</th>
            <th class="py-2 font-medium">Keterangan</th>
        </tr>
    </thead>
    <tbody class="divide-y divide-slate-100">
        @foreach ($securityChecks as $key)
            @continue(! isset($observations[$key]))
            <tr class="align-top">
                <td class="py-2 pr-4">{{ $observations[$key]->label }}</td>
                <td class="py-2 pr-4">
                    <x-badge :class="$observations[$key]->status->badgeClass()">{{ $observations[$key]->status->value }}</x-badge>
                </td>
                <td class="py-2 wrap-break-word text-slate-700">{{ $observations[$key]->summary }}</td>
            </tr>
        @endforeach
    </tbody>
</table>
