<?php

namespace Tests;

use Illuminate\Contracts\Console\Kernel;
use Illuminate\Encryption\Encrypter;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Testing\TestCase as BaseTestCase;
use Illuminate\Support\Facades\Http;

abstract class TestCase extends BaseTestCase
{
    public function createApplication(): Application
    {
        $application = require dirname(__DIR__).'/bootstrap/app.php';

        // Load only the checked-in template; PHPUnit and CI provide isolated overrides.
        $application->loadEnvironmentFrom('.env.example');
        $this->traitsUsedByTest = class_uses_recursive(static::class);
        $application->make(Kernel::class)->bootstrap();

        return $application;
    }

    protected function setUp(): void
    {
        parent::setUp();

        // Test requests use an ephemeral key, never a developer or production key.
        config(['app.key' => 'base64:'.base64_encode(Encrypter::generateKey(config('app.cipher')))]);

        Http::preventStrayRequests();
        // Exercise Laravel's real breach validator with deterministic k-anonymity responses.
        Http::fake(['api.pwnedpasswords.com/range/*' => Http::response(substr(strtoupper(sha1('password123')), 5).":100000\n")]);
    }
}
