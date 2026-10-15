@props(['name', 'url' => null])
@if($url)
    <img class="application-logo" src="{{ $url }}" alt="{{ $name }} logo" width="48" height="48">
@else
    <span class="application-logo application-logo--fallback" role="img" aria-label="{{ $name }} logo">{{ mb_strtoupper(mb_substr(trim($name), 0, 2)) }}</span>
@endif
