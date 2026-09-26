@php
    $overview = $target->overview ?? [];
    $wafBlocked = ! empty($overview['waf_blocked']);
    $tls = $overview['tls'] ?? null;

    $rows = [
        'URL' => $target->url,
        'URL Final' => $overview['final_url'] ?? '-',
        'IP Address' => implode(', ', $overview['ip_addresses'] ?? []) ?: '-',
        'HTTP Status' => $overview['http_status'] ?? '-',
        'HTTPS' => match ($overview['https'] ?? null) { true => 'Ya', false => 'Tidak', default => '-' },
        'Title' => ($overview['title'] ?? '-').($wafBlocked ? ' (halaman WAF/CDN)' : ''),
        'Web Server' => $overview['web_server'] ?? '-',
        'X-Powered-By' => $overview['powered_by'] ?? '-',
        'CDN/WAF' => implode(', ', $overview['cdn'] ?? []) ?: '-',
        'CMS' => $overview['cms'] ?? '-',
        'TLS' => $tls === null ? '-' : implode(' · ', array_filter([
            $tls['protocol'] ?? null,
            $tls['issuer'] ?? null,
            'berlaku hingga '.($tls['valid_to'] ?? '-').(isset($tls['days_left']) ? " ({$tls['days_left']} hari)" : ''),
        ])),
        'Protokol TLS Didukung' => implode(', ', $overview['tls_protocols'] ?? []) ?: '-',
        'Port Terbuka' => implode(', ', array_map(fn ($p) => $p['port'].(! empty($p['service']) ? '/'.$p['service'] : ''), $overview['open_ports'] ?? [])) ?: '-',
        'Waktu Pemeriksaan' => $target->started_at
            ? $target->started_at->format('d-m-Y H:i:s').($target->finished_at ? ' s.d. '.$target->finished_at->format('H:i:s') : '')
            : '-',
    ];
@endphp

@if ($wafBlocked)
    <p class="mb-4 rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-800">
        Halaman utama yang diterima SIPRIKA berupa halaman blokir atau tantangan WAF/CDN, sehingga pemeriksaan header, cookie, dan exposure tidak dapat dinilai (NOT ASSESSED).
        Tambahkan pengecualian (allowlist) untuk User-Agent atau IP SIPRIKA di pengaturan WAF/CDN, lalu periksa ulang.
    </p>
@endif

<dl class="grid grid-cols-1 gap-x-8 gap-y-3 text-sm sm:grid-cols-2">
    @foreach ($rows as $label => $value)
        <div>
            <dt class="text-slate-500">{{ $label }}</dt>
            <dd class="font-medium break-all">{{ $value }}</dd>
        </div>
    @endforeach
</dl>

<h2 class="mt-8 text-sm font-semibold text-slate-900">Technology</h2>
@if (! empty($overview['technologies']))
    <div class="mt-2 flex flex-wrap gap-2">
        @foreach ($overview['technologies'] as $technology)
            <span class="rounded-md bg-slate-100 px-2 py-1 text-xs text-slate-700" title="{{ $technology['category'] }} ({{ $technology['source'] }})">
                {{ $technology['name'] }}@if ($technology['version']) {{ $technology['version'] }}@endif
            </span>
        @endforeach
    </div>
@else
    <p class="mt-2 text-sm text-slate-500">Tidak ada teknologi yang dikenali.</p>
@endif
