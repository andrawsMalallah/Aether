<?php

use Illuminate\Database\Connection;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        $connection = DB::connection($this->getConnection());
        if ($connection->getDriverName() !== 'pgsql') {
            throw new RuntimeException('The access-token baseline requires PostgreSQL.');
        }
        $connection->transaction(function (Connection $connection): void {
            $connection->statement("SET LOCAL lock_timeout = '5s'");
            $connection->statement("SET LOCAL statement_timeout = '30s'");
            Schema::connection($connection->getName())->create('oauth_access_tokens', function (Blueprint $table): void {
                $table->char('id', 80)->primary();
                $table->foreignId('user_id')->nullable()->index();
                $table->foreignUuid('client_id')->index();
                $table->string('name')->nullable();
                $table->text('scopes')->nullable();
                $table->boolean('revoked');
                $table->timestamps();
                $table->dateTime('expires_at')->nullable()->index();
                // Family lineage and identity context must survive authorization-code cleanup.
                $table->char('auth_code_id', 80)->nullable()->index();
                $table->text('oidc_nonce')->nullable();
                $table->unsignedBigInteger('oidc_auth_time')->nullable();
            });
            // Laravel's index builder has no PostgreSQL INCLUDE support.
            $connection->statement('CREATE INDEX oauth_access_tokens_retention_family_index ON oauth_access_tokens (auth_code_id, client_id, user_id, expires_at) INCLUDE (id)');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('oauth_access_tokens');
    }

    /**
     * Get the migration connection name.
     */
    public function getConnection(): ?string
    {
        return $this->connection ?? config('passport.connection');
    }
};
