<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('oauth_clients', function (Blueprint $table): void {
            // Privileged resource permission; never writable through client-profile input.
            $table->json('introspection_client_ids')->nullable();
        });
    }

    public function down(): void
    {
        Schema::table('oauth_clients', fn (Blueprint $table) => $table->dropColumn('introspection_client_ids'));
    }
};
