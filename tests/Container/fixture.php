<?php

// Used only by scripts/test-container.ps1 with a fresh private fixture network.
use App\Actions\Account\RequestAccountExport;
use App\Enums\AccountExportStatus;
use App\Models\AccountExport;
use App\Models\User;
use App\Services\PrivateStorage;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Cookie\CookieValuePrefix;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

try {
    if (($argv[1] ?? '') === 'environment') {
        $private = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($private, $pem);
        $public = openssl_pkey_get_details($private)['key'];
        $password = bin2hex(random_bytes(24));
        $lines = [
            'APP_ENV=production', 'APP_DEBUG=false', 'APP_URL=https://container.example',
            'APP_KEY=base64:'.base64_encode(random_bytes(32)),
            'PASSPORT_PRIVATE_KEY='.str_replace("\n", '\\n', $pem),
            'PASSPORT_PUBLIC_KEY='.str_replace("\n", '\\n', $public),
            'DB_CONNECTION=pgsql', 'DB_HOST='.getenv('FIXTURE_DATABASE_HOST'), 'DB_PORT=5432',
            'DB_DATABASE=aether_container', 'DB_USERNAME=fixture', 'DB_PASSWORD='.$password, 'DB_SSLMODE=disable',
            'SESSION_DRIVER=database', 'SESSION_SECURE_COOKIE=true', 'CACHE_STORE=database',
            'QUEUE_CONNECTION=database', 'DB_QUEUE=default', 'DB_QUEUE_RETRY_AFTER=90',
            'MAIL_MAILER=smtp', 'MAIL_HOST='.getenv('FIXTURE_MAIL_HOST'), 'MAIL_PORT=1025', 'MAIL_FROM_ADDRESS=fixture@example.com',
            'AETHER_PRIVATE_DISK=private_s3', 'AWS_ACCESS_KEY_ID=fixture', 'AWS_SECRET_ACCESS_KEY=fixture',
            'AWS_DEFAULT_REGION=us-east-1', 'AWS_BUCKET=fixture', 'AETHER_STORAGE_PREFIX=isolated',
            'AWS_ENDPOINT=https://'.getenv('FIXTURE_STORAGE_HOST').':9191', 'AWS_USE_PATH_STYLE_ENDPOINT=true',
            'LOG_CHANNEL=stderr', 'AETHER_RETENTION_ENABLED=false',
        ];
        file_put_contents('/fixture/runtime.env', implode("\n", $lines)."\n");
        file_put_contents('/fixture/database.env', "POSTGRES_USER=fixture\nPOSTGRES_DB=aether_container\nPOSTGRES_PASSWORD=".$password."\n");
        exit;
    }

    require '/var/www/html/vendor/autoload.php';
    $application = require '/var/www/html/bootstrap/app.php';
    $application->make(Kernel::class)->bootstrap();
    if (config('database.connections.pgsql.database') !== 'aether_container'
        || ! str_starts_with((string) config('database.connections.pgsql.host'), 'aether-container-')) {
        throw new RuntimeException('Container fixture target rejected.');
    }

    switch ($argv[1] ?? '') {
        case 'integration-guides':
            $browserGuide = view('developer.vue-example')->render();
            $machineGuide = view('developer.machine-example')->render();
            foreach (['auth.js', 'App.vue', 'example.css'] as $filename) {
                $source = file_get_contents(resource_path('examples/browser/'.$filename));
                if ($source === false || $source === '' || ! str_contains($browserGuide, e($source))) {
                    throw new RuntimeException('Browser integration guide is incomplete.');
                }
            }
            foreach (['aether-machine.php', 'ReadAetherStats.php'] as $filename) {
                $source = file_get_contents(resource_path('examples/machine/'.$filename));
                if ($source === false || $source === '' || ! str_contains($machineGuide, e($source))) {
                    throw new RuntimeException('Machine integration guide is incomplete.');
                }
            }
            echo "Browser and Machine integration guides rendered with complete examples.\n";
            break;
        case 'produce':
            $user = new User;
            $user->forceFill(['name' => 'Container fixture', 'email' => 'container@example.com',
                'password' => password_hash(bin2hex(random_bytes(24)), PASSWORD_ARGON2ID), 'email_verified_at' => now()])->save();
            Auth::login($user);
            $export = app(RequestAccountExport::class)->handle($user);
            Cache::put('container-fixture', $export->id, 600);
            $lock = Cache::lock('container-lock', 30);
            if (! $lock->get()) {
                throw new RuntimeException('Fixture lock failed.');
            }
            $lock->release();
            $payload = DB::table('jobs')->value('payload');
            if (! is_string($payload) || str_contains($payload, 'container@example.com') || str_contains($payload, $export->id)) {
                throw new RuntimeException('Queue fixture encryption failed.');
            }
            echo "Encrypted export queued; shared cache and lock passed.\n";
            break;
        case 'verify':
            $export = AccountExport::findOrFail(Cache::get('container-fixture'));
            if ($export->status !== AccountExportStatus::Ready || ! app(PrivateStorage::class)->disk()->exists($export->relativePath())
                || DB::table('jobs')->count() !== 0 || DB::table('failed_jobs')->count() !== 0) {
                throw new RuntimeException('Fixture export delivery failed.');
            }
            echo "Shared private export and queue completion passed.\n";
            break;
        case 'log':
            Log::error('CONTAINER_SENSITIVE_CANARY', ['token' => 'CONTAINER_SENSITIVE_CANARY', 'exception' => new RuntimeException('CONTAINER_SENSITIVE_CANARY')]);
            echo "Safe log fixture completed.\n";
            break;
        case 'drain-produce':
            ContainerBoundedJob::dispatch();
            break;
        case 'drain-started':
            exit(Cache::get('container-drain-started') === true ? 0 : 1);
        case 'drain-verify':
            exit(Cache::get('container-drain-finished') === true && DB::table('jobs')->count() === 0 ? 0 : 1);
        case 'download-session':
            $export = AccountExport::findOrFail(Cache::get('container-fixture'));
            if (! $export->available() || ! PrivateStorage::disk()->exists($export->relativePath())) {
                throw new RuntimeException('Fixture export unavailable before download.');
            }
            session()->start();
            Auth::login(User::findOrFail($export->user_id));
            session(['auth.password_confirmed_at' => now()->timestamp]);
            session()->save();
            $name = config('session.cookie');
            $cookie = Crypt::encryptString(CookieValuePrefix::create($name, Crypt::getKey()).session()->getId());
            file_put_contents('/tmp/container-download.json', json_encode([
                'path' => '/account/export/'.$export->id.'/download', 'cookie' => $name.'='.rawurlencode($cookie),
            ], JSON_THROW_ON_ERROR));
            break;
        case 'expire':
            AccountExport::findOrFail(Cache::get('container-fixture'))->update(['expires_at' => now()->startOfHour()->subSecond()]);
            break;
        case 'download-check':
        case 'expired-check':
            $download = json_decode(file_get_contents('/tmp/container-download.json'), true, flags: JSON_THROW_ON_ERROR);
            $receivedBytes = 0;
            $request = curl_init('http://127.0.0.1:10000'.$download['path']);
            curl_setopt_array($request, [CURLOPT_HTTPHEADER => ['Cookie: '.$download['cookie'], 'Accept: application/json'],
                CURLOPT_TIMEOUT => 5, CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_WRITEFUNCTION => function ($connection, string $bytes) use (&$receivedBytes): int {
                    $receivedBytes += strlen($bytes);

                    return strlen($bytes);
                }]);
            if (curl_exec($request) === false) {
                throw new RuntimeException('Fixture HTTP download failed.');
            }
            $status = curl_getinfo($request, CURLINFO_HTTP_CODE);
            $type = curl_getinfo($request, CURLINFO_CONTENT_TYPE);
            $expected = $argv[1] === 'download-check' ? 200 : 404;
            if ($status !== $expected || ($expected === 200 && ($receivedBytes < 10 || ! str_starts_with($type, 'application/json')))) {
                throw new RuntimeException('Fixture protected download assertion failed.');
            }
            echo "Protected HTTP download assertion passed.\n";
            break;
        case 'schedule-hour':
            // Only this fresh fixture target is accepted above. Exercise real hourly tasks.
            Carbon::setTestNow(now()->startOfHour());
            Artisan::call('schedule:run');
            echo "Isolated hourly scheduler completed.\n";
            break;
        case 'expiry-verify':
            $export = AccountExport::findOrFail(Cache::get('container-fixture'));
            exit($export->status === AccountExportStatus::Expired && ! PrivateStorage::disk()->exists($export->relativePath()) ? 0 : 1);
        default:
            throw new RuntimeException('Unknown fixture command.');
    }
} catch (Throwable) {
    // Laravel's installed exception renderer can otherwise leave this standalone
    // fixture process with a successful status despite a failed assertion.
    fwrite(STDERR, "Container fixture assertion failed.\n");
    exit(1);
}
