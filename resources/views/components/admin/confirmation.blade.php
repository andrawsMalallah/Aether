@props(['application', 'title', 'description', 'confirmation', 'action'])
<x-layout :title="$title">
    <x-ui.header />
    <main id="main-content" class="account-content">
        <a href="{{ route('admin.apps.show', $application['id']) }}">Back to application</a>
        <h1>{{ $title }}</h1>
        <h2 class="developer-application-name">{{ $application['name'] }}</h2>
        <p class="notice">{{ $description }}</p>
        <form method="POST" action="{{ $action }}" data-submit-form>
            @csrf
            <label class="checkbox">
                <input type="checkbox" name="confirm" value="1" required aria-invalid="{{ $errors->has('confirm') ? 'true' : 'false' }}" @if($errors->has('confirm')) aria-describedby="confirm-error" @endif>
                <span>{{ $confirmation }}</span>
            </label>
            @error('confirm')<p id="confirm-error" class="field__error" role="alert">Confirm that you want to continue.</p>@enderror
            <x-ui.button>{{ $title }}</x-ui.button>
        </form>
    </main>
</x-layout>
