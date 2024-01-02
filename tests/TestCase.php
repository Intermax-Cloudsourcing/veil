<?php

declare(strict_types=1);

namespace Intermax\Veil\Tests;

use Intermax\Veil\Providers\VeilServiceProvider;
use Orchestra\Testbench\TestCase as BaseTestCase;

abstract class TestCase extends BaseTestCase
{
    protected function getPackageProviders($app): array
    {
        return [VeilServiceProvider::class];
    }
}
