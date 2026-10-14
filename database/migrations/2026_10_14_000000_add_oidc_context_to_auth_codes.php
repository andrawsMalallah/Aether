<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('oauth_auth_codes', function (Blueprint $table): void {
            // Bind identity context to the code, without changing Passport's credential format.
            $table->text('oidc_nonce')->nullable();
            $table->unsignedBigInteger('oidc_auth_time')->nullable();
        });
        Schema::table('oauth_access_tokens', function (Blueprint $table): void {
            // Refresh context must survive routine purging of expired authorization codes.
            $table->text('oidc_nonce')->nullable();
            $table->unsignedBigInteger('oidc_auth_time')->nullable();
        });
    }

    public function down(): void
    {
        Schema::table('oauth_auth_codes', function (Blueprint $table): void {
            $table->dropColumn(['oidc_nonce', 'oidc_auth_time']);
        });
        Schema::table('oauth_access_tokens', function (Blueprint $table): void {
            $table->dropColumn(['oidc_nonce', 'oidc_auth_time']);
        });
    }
};
