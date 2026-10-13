@props(['name', 'label', 'type' => 'text', 'value' => null, 'autocomplete' => null, 'help' => null, 'id' => null])
@php($fieldId = $id ?? $name)
<div class="field">
    <label for="{{ $fieldId }}">{{ $label }}</label>
    <input id="{{ $fieldId }}" name="{{ $name }}" type="{{ $type }}"
        @if(!in_array($type, ['password', 'file'], true)) value="{{ old($name, $value) }}" @endif
        @if($autocomplete) autocomplete="{{ $autocomplete }}" @endif
        @if($help || $errors->has($name)) aria-describedby="{{ $fieldId }}-help" @endif
        aria-invalid="{{ $errors->has($name) ? 'true' : 'false' }}" {{ $attributes }}>
    @if($errors->has($name))
        <p id="{{ $fieldId }}-help" class="field__error">{{ $errors->first($name) }}</p>
    @elseif($help)
        <p id="{{ $fieldId }}-help" class="field__help">{{ $help }}</p>
    @endif
</div>
