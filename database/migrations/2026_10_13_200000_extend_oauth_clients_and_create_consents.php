<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('oauth_clients', function (Blueprint $table): void {
            $table->boolean('first_party')->default(false);
            $table->string('logo_path')->nullable();
            $table->string('homepage_url')->nullable();
            $table->string('status')->default('testing')->index();
            $table->string('app_type')->default('web');
            $table->json('allowed_scopes')->nullable();
        });
        Schema::table('oauth_access_tokens', function (Blueprint $table): void {
            // Preserve code lineage across refreshes so a code replay can revoke its tokens.
            $table->char('auth_code_id', 80)->nullable()->index();
            $table->index('client_id');
            $table->index('expires_at');
        });
        Schema::table('oauth_auth_codes', function (Blueprint $table): void {
            $table->index('client_id');
            $table->index('expires_at');
        });
        Schema::table('oauth_refresh_tokens', function (Blueprint $table): void {
            $table->index('expires_at');
        });
        Schema::create('consents', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('user_id')->constrained();
            $table->foreignUuid('client_id')->constrained('oauth_clients');
            $table->json('scopes');
            $table->timestamp('granted_at');
            $table->timestamp('revoked_at')->nullable();
            $table->timestamps();
            $table->unique(['user_id', 'client_id']);
            $table->index('client_id');
        });
        Schema::create('audit_logs', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('user_id')->nullable()->index();
            $table->foreignUuid('client_id')->nullable()->index();
            $table->string('event');
            $table->timestamp('created_at')->index();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('audit_logs');
        Schema::dropIfExists('consents');
        Schema::table('oauth_refresh_tokens', fn (Blueprint $table) => $table->dropIndex(['expires_at']));
        Schema::table('oauth_auth_codes', function (Blueprint $table): void {
            $table->dropIndex(['client_id']);
            $table->dropIndex(['expires_at']);
        });
        Schema::table('oauth_access_tokens', function (Blueprint $table): void {
            $table->dropIndex(['client_id']);
            $table->dropIndex(['expires_at']);
            $table->dropIndex(['auth_code_id']);
            $table->dropColumn('auth_code_id');
        });
        Schema::table('oauth_clients', function (Blueprint $table): void {
            $table->dropIndex(['status']);
            $table->dropColumn(['first_party', 'logo_path', 'homepage_url', 'status', 'app_type', 'allowed_scopes']);
        });
    }
};
