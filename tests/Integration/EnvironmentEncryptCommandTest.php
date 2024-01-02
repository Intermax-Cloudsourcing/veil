<?php

declare(strict_types=1);

use Illuminate\Encryption\Encrypter;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Facades\File;
use Mockery as m;

beforeEach(function () {
    $this->filesystem = m::spy(Filesystem::class);
    $this->filesystem->shouldReceive('get')
        ->andReturn(true)->byDefault()
        ->shouldReceive('put')
        ->andReturn('APP_NAME=Laravel')->byDefault();
    File::swap($this->filesystem);
});

it('encrypts the values of an environment', function () {
    $contents = <<<'Text'
        APP_NAME=Laravel
        APP_ENV=local
        APP_DEBUG=true
        APP_URL=http://localhost
        Text;

    $this->filesystem->shouldReceive('exists')
        ->once()
        ->andReturn(true)
        ->shouldReceive('exists')
        ->once()
        ->andReturn(false)
        ->shouldReceive('get')
        ->andReturn($contents)
        ->shouldReceive('put')
        ->withArgs(function ($file, $contents) {
            $encrypter = new Encrypter('abcdefghijklmnopabcdefghijklmnop', 'AES-256-CBC');

            $this->assertStringContainsString('APP_NAME', $contents);
            $this->assertStringContainsString('APP_ENV', $contents);
            $this->assertStringContainsString('APP_DEBUG', $contents);
            $this->assertStringContainsString('APP_URL', $contents);

            $this->assertEquals('Laravel', $encrypter->decrypt(Str::betweenFirst($contents, '=', "\n")));

            return true;
        })->andReturn(true);

    $this->artisan('env:encrypt', ['--env' => 'production', '--key' => 'abcdefghijklmnopabcdefghijklmnop', '--only-values' => true])
        ->expectsOutputToContain('Environment successfully encrypted.')
        ->assertExitCode(0);
});
