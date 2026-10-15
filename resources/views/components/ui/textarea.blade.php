@props(['name', 'label', 'value' => null, 'help' => null, 'errorName' => null])
@php($fieldError = $errors->first($name) ?: ($errorName ? $errors->first($errorName) : null))
<div class="field">
    <label for="{{ $name }}">{{ $label }}</label>
    <textarea id="{{ $name }}" name="{{ $name }}" aria-invalid="{{ $fieldError ? 'true' : 'false' }}"
        @if($help || $fieldError) aria-describedby="{{ $name }}-help" @endif {{ $attributes }}>{{ old($name, $value) }}</textarea>
    @if($fieldError)
        <p id="{{ $name }}-help" class="field__error">{{ $fieldError }}</p>
    @elseif($help)
        <p id="{{ $name }}-help" class="field__help">{{ $help }}</p>
    @endif
</div>
