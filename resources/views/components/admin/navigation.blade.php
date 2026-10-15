<nav class="developer-actions" aria-label="Administration sections">
    <a href="{{ route('admin.apps.index') }}" @if(request()->routeIs('admin.apps.*')) aria-current="page" @endif>Applications</a>
    <a href="{{ route('admin.users.index') }}" @if(request()->routeIs('admin.users.*')) aria-current="page" @endif>Users</a>
    <a href="{{ route('admin.audit.index') }}" @if(request()->routeIs('admin.audit.*')) aria-current="page" @endif>Audit log</a>
</nav>
