<?php

declare(strict_types=1);

use Illuminate\Encryption\Encrypter;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Str;
use Mockery as m;

beforeEach(function () {
    $this->filesystem = m::spy(Filesystem::class);
    $this->filesystem->shouldReceive('get')
        ->andReturn(true)->byDefault()
        ->shouldReceive('put')
        ->andReturn('APP_NAME=Laravel')->byDefault();
    File::swap($this->filesystem);
});

it('encrypts the secrets of an environment', function () {
    $contents = <<<'Text'
        APP_KEY=1234
        APP_NAME=Laravel
        APP_ENV=local
        APP_DEBUG=true
        APP_URL=http://localhost
        API_TOKEN=secret
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
            $this->assertStringContainsString('APP_KEY', $contents);
            $this->assertStringContainsString('http://localhost', $contents);

            $this->assertEquals('1234', $encrypter->decrypt(Str::betweenFirst($contents, '=', "\n")));
            $this->assertEquals('secret', $encrypter->decrypt(Str::afterLast($contents, '=')));

            return true;
        })->andReturn(true);

    $this->artisan('env:encrypt', ['--env' => 'production', '--key' => 'abcdefghijklmnopabcdefghijklmnop', '--only-values' => true])
        ->expectsOutputToContain('Environment successfully encrypted.')
        ->assertExitCode(0);
});

it('encrypts the secrets of an environment using the line endings of the file', function () {
    $contents = implode("\r\n", [
        'APP_KEY=1234',
        'APP_NAME=Laravel',
        'APP_ENV=local',
        'API_TOKEN=secret',
    ]);

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

            $lines = explode("\r\n", $contents);

            $this->assertCount(4, $lines);
            $this->assertStringNotContainsString("\r", implode('', $lines));

            $this->assertSame('APP_NAME=Laravel', $lines[1]);
            $this->assertSame('APP_ENV=local', $lines[2]);

            $this->assertSame('1234', $encrypter->decrypt(Str::after($lines[0], 'APP_KEY=')));
            $this->assertSame('secret', $encrypter->decrypt(Str::after($lines[3], 'API_TOKEN=')));

            return true;
        })->andReturn(true);

    $this->artisan('env:encrypt', ['--env' => 'production', '--key' => 'abcdefghijklmnopabcdefghijklmnop', '--only-values' => true])
        ->expectsOutputToContain('Environment successfully encrypted.')
        ->assertExitCode(0);
});
