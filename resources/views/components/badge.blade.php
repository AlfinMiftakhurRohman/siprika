{{-- Label status berwarna, contoh: <x-badge :class="$observation->status->badgeClass()">PASS</x-badge> --}}
<span {{ $attributes->merge(['class' => 'inline-block rounded-full px-2.5 py-0.5 text-xs font-medium']) }}>{{ $slot }}</span>
