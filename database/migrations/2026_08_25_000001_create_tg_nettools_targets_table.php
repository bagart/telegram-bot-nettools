<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Target memory schema (RFC §3.7): hosts remembered per user, habit-ranked
 * quick actions. LRU cap 25 enforced by the repository (pinned exempt).
 */
return new class () extends Migration {
    public function up(): void
    {
        Schema::create('tg_nettools_targets', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('user_id');
            $table->string('host');
            $table->string('label')->nullable();
            $table->boolean('pinned')->default(false);
            $table->unsignedInteger('use_count')->default(0);
            $table->json('habits')->default('{}');
            $table->timestamp('last_used_at')->nullable();
            $table->timestamps();

            $table->unique(['user_id', 'host']);
            $table->index(['user_id', 'last_used_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('tg_nettools_targets');
    }
};
