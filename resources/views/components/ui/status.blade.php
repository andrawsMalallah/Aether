@if(session('status'))
    <p class="notice" role="status">{{ session('status') === 'verification-link-sent' ? 'A new verification link has been sent to your email address.' : session('status') }}</p>
@endif
@if($errors->any())
    <div class="notice notice--error" role="alert">
        <p>Please check the information below.</p>
        <ul>
            @foreach($errors->all() as $error)
                <li>{{ $error }}</li>
            @endforeach
        </ul>
    </div>
@endif
