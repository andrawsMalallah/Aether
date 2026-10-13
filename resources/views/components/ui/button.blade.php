@props(['variant' => 'primary', 'type' => 'submit'])
<button type="{{ $type }}" {{ $attributes->class(['button', 'button--'.$variant]) }}>{{ $slot }}</button>
