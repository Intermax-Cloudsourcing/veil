<?php

declare(strict_types=1);

namespace Intermax\Veil\Providers;

use Illuminate\Foundation\Console\EnvironmentDecryptCommand as BaseDecryptCommand;
use Illuminate\Foundation\Console\EnvironmentEncryptCommand as BaseEncryptCommand;
use Illuminate\Support\ServiceProvider;
use Intermax\Veil\Console\EnvironmentDecryptCommand;
use Intermax\Veil\Console\EnvironmentEncryptCommand;

class VeilServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->extend(BaseEncryptCommand::class, function () {
            return $this->app->make(EnvironmentEncryptCommand::class);
        });

        $this->app->extend(BaseDecryptCommand::class, function () {
            return $this->app->make(EnvironmentDecryptCommand::class);
        });
    }

    public function boot(): void {}
}
