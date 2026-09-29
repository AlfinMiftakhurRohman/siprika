{{--
    Risk Register dengan tata letak sheet "Perangkat Lunak" pada template (baris judul, header 3 baris,
    kolom A sampai AA). Isi kolom sama dengan export Excel (App\Risk\RiskRegisterSheet).
    Variabel: $items (koleksi RiskRegisterItem, urut sesuai nomor risiko).
--}}
@use('App\Models\RiskRegisterItem')
@use('App\Risk\RiskRegisterSheet')

@php
    // Lebar kolom dari template (satuan karakter Excel)
    $widths = [
        'A' => 8.6, 'B' => 15.5, 'C' => 26.4, 'D' => 23.8, 'E' => 23.8, 'F' => 19.8, 'G' => 32, 'H' => 19.4, 'I' => 20,
        'J' => 12, 'K' => 13.8, 'L' => 8.2, 'M' => 16, 'N' => 16.5, 'O' => 12, 'P' => 16.8, 'Q' => 26, 'R' => 26.5,
        'S' => 16.2, 'T' => 13, 'U' => 12.5, 'V' => 11, 'W' => 12.6, 'X' => 8, 'Y' => 12, 'Z' => 26, 'AA' => 14,
    ];
    $center = ['A', 'B', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'U', 'V', 'W', 'X', 'Y'];
    $aiColumns = ['G', 'Q', 'Z'];
    $levelClasses = array_map(fn (array $level) => $level['cell'], RiskRegisterItem::LEVELS);
    $blue = 'bg-[#2F75B5] text-white';
    $red = 'bg-[#C00000] text-white';
    $green = 'bg-[#00B050] text-white';
    $head = 'border border-slate-800 px-1.5 py-1 text-center align-middle font-bold';
@endphp

@if ($items->isEmpty())
    <p class="text-sm text-slate-500">Belum ada baris Risk Register.</p>
@else
    <div class="overflow-x-auto rounded border border-slate-300 bg-white">
        <table class="table-fixed border-collapse text-[11px] leading-snug text-slate-900" style="width: {{ array_sum(array_map(fn ($w) => round($w * 7 + 5), $widths)) }}px">
            <colgroup>
                @foreach ($widths as $width)
                    <col style="width: {{ round($width * 7 + 5) }}px">
                @endforeach
            </colgroup>
            <thead>
                <tr>
                    <th colspan="3" class="border border-slate-300 py-2">
                        <img src="{{ asset('images/logo-risk-register.png') }}" alt="Logo" class="mx-auto h-14 w-14">
                    </th>
                    <th colspan="18" class="border border-slate-300 py-2 text-base font-bold">
                        REGISTER RISIKO KEAMANAN INFORMASI<br>(ASET: PERANGKAT LUNAK)
                    </th>
                    <th colspan="2" class="border border-slate-300 px-1.5 text-right font-normal">Revisi</th>
                    <th class="border border-slate-300"></th>
                    <th class="border border-slate-300 px-1.5 text-left font-normal">Tanggal:</th>
                    <th colspan="2" class="border border-slate-300 px-1.5 text-left font-normal">Dokumen:</th>
                </tr>
                <tr>
                    <th rowspan="3" class="{{ $head }} {{ $blue }}">Risk No</th>
                    <th rowspan="3" class="{{ $head }} {{ $blue }}">Jenis Risiko</th>
                    <th colspan="6" class="{{ $head }} {{ $red }} text-xs">Identifikasi Resiko</th>
                    <th rowspan="3" class="{{ $head }} {{ $blue }}">Kontrol Saat Ini</th>
                    <th colspan="4" rowspan="2" class="{{ $head }} {{ $blue }}">Nilai Resiko Bawaan (Inherent Risk)</th>
                    <th colspan="2" class="{{ $head }} {{ $blue }} text-xs">EVALUASI RISIKO</th>
                    <th colspan="6" class="{{ $head }} {{ $green }} text-xs">RENCANA PENANGANAN RISIKO</th>
                    <th colspan="4" class="{{ $head }} {{ $blue }}">Residual Risk</th>
                    <th rowspan="3" class="{{ $head }} {{ $blue }}">Rencana Kontrol Tambahan</th>
                    <th rowspan="3" class="{{ $head }} {{ $blue }}">Risk Owner</th>
                </tr>
                <tr>
                    @foreach (['Aset', 'Ancaman', 'Kerawanan/Kelemahan', 'Kategori', 'Dampak', 'Area Dampak'] as $label)
                        <th rowspan="2" class="{{ $head }} {{ $red }}">{{ $label }}</th>
                    @endforeach
                    @foreach (['Keputusan Penanganan Risiko', 'Prioritas Risiko'] as $label)
                        <th rowspan="2" class="{{ $head }} {{ $blue }}">{{ $label }}</th>
                    @endforeach
                    @foreach (['Opsi Penanganan', 'Rencana Aksi Penanganan Risiko', 'Keluaran', 'Target/Jadwal Implementasi', 'Penanggung Jawab', 'Apakah Terdapat Residual Risk'] as $label)
                        <th rowspan="2" class="{{ $head }} {{ $green }}">{{ $label }}</th>
                    @endforeach
                    @foreach (['Dampak', 'Kemungkinan', 'RR', 'Status'] as $label)
                        <th rowspan="2" class="{{ $head }} {{ $blue }}">{{ $label }}</th>
                    @endforeach
                </tr>
                <tr>
                    @foreach (['Dampak', 'Kemungkinan', 'IR', 'Level Risiko'] as $label)
                        <th class="{{ $head }} {{ $blue }}">{{ $label }}</th>
                    @endforeach
                </tr>
            </thead>
            <tbody>
                @foreach ($items->values() as $index => $item)
                    @php($values = RiskRegisterSheet::displayValues($item, $index + 1))
                    <tr>
                        @foreach (array_keys($widths) as $column)
                            <td @class([
                                'border border-slate-400 px-1.5 py-1 align-top whitespace-pre-line break-words',
                                'text-center' => in_array($column, $center, true),
                                'font-semibold' => in_array($column, ['L', 'M', 'X', 'Y'], true),
                                $levelClasses[$item->risk_level] ?? '' => in_array($column, ['L', 'M'], true),
                            ])
                                @if (in_array($column, $aiColumns, true)) title="Teks: {{ $item->textSourceLabel() }}" @endif
                                @if ($column === 'L') title="{{ $item->risk_status }}" @endif
                            >{{ $values[$column] ?? '' }}</td>
                        @endforeach
                    </tr>
                @endforeach
            </tbody>
        </table>
    </div>
    <p class="mt-2 text-xs text-slate-500">
        Kolom Target/Jadwal, Penanggung Jawab, dan Risk Owner sengaja kosong untuk diisi staf (bagian 17).
        Residual Risk adalah perkiraan risiko setelah Rencana Aksi dijalankan, bukan hasil pengukuran (bagian 24.6).
        Arahkan kursor ke kolom Dampak, Rencana Aksi, atau Rencana Kontrol Tambahan untuk melihat asal teksnya (AI atau katalog).
    </p>
@endif
