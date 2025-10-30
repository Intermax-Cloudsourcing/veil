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
        ->andReturn(true, false, false)
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

            $this->assertEquals('1234', $encrypter->decrypt(Str::betweenFirst($contents, 'APP_KEY=', PHP_EOL)));
            $this->assertEquals('secret', $encrypter->decrypt(Str::betweenFirst($contents, 'API_TOKEN=', PHP_EOL)));

            return true;
        })->andReturn(true);

    $this->artisan('env:encrypt', ['--env' => 'production', '--key' => 'abcdefghijklmnopabcdefghijklmnop', '--only-values' => true])
        ->expectsOutputToContain('Environment successfully encrypted.')
        ->assertExitCode(0);
});


it('prevents rotating unchanged already encrypted secrets', function () {
    $plainContents = <<<'Text'
        APP_KEY=1234
        APP_NAME=Laravel
        APP_ENV=local
        APP_DEBUG=true
        APP_URL=http://localhost
        API_TOKEN=secret
        NEW_SECRET=newvalue
        CHANGED_SECRET=secret-2
        Text;

    $encrypter = new Encrypter('abcdefghijklmnopabcdefghijklmnop', 'AES-256-CBC');

    $encryptedAppKey = $encrypter->encrypt('1234');
    $encryptedApiToken = $encrypter->encrypt('secret');
    $encryptedChangedSecret = $encrypter->encrypt('secret-1');

    $existingEncryptedContents = implode(PHP_EOL, [
        "APP_KEY={$encryptedAppKey}",
        "API_TOKEN={$encryptedApiToken}",
        "CHANGED_SECRET={$encryptedChangedSecret}",
    ]);

    $this->filesystem->shouldReceive('exists')
        ->andReturn(true, true, true)
        ->shouldReceive('get')
        ->andReturn($plainContents, $existingEncryptedContents)
        ->shouldReceive('put')
        ->withArgs(function ($file, $contents) use ($encryptedAppKey, $encryptedApiToken) {
            // The command should reuse existing encrypted values, not rotate them
            $this->assertEquals($encryptedAppKey, Str::betweenFirst($contents, 'APP_KEY=', PHP_EOL));
            $this->assertEquals($encryptedApiToken, Str::betweenFirst($contents, 'API_TOKEN=', PHP_EOL));

            // The command should encrypt changed secrets
            $this->assertNotEquals($encryptedAppKey, Str::betweenFirst($contents, 'CHANGED_SECRET=', PHP_EOL));

            // The command should encrypt new secrets
            $this->assertNotEquals($encryptedAppKey, Str::betweenFirst($contents, 'NEW_SECRET=', PHP_EOL));

            // Still keeps non-matching keys readable
            $this->assertStringContainsString('APP_NAME=Laravel' . PHP_EOL, $contents);
            $this->assertStringContainsString('APP_ENV=local' . PHP_EOL, $contents);
            $this->assertStringContainsString('APP_DEBUG=true' . PHP_EOL, $contents);
            $this->assertStringContainsString('APP_URL=http://localhost' . PHP_EOL, $contents);

            return true;
        })
        ->andReturnTrue();

    $this->artisan('env:encrypt', ['--env' => 'production', '--key' => 'abcdefghijklmnopabcdefghijklmnop', '--only-values' => true, '--force' => true])
        ->expectsOutputToContain('Environment successfully encrypted.')
        ->assertExitCode(0);
});


it('does not encrypt known safe values such as null', function () {
    $contents = <<<'Text'
        APP_KEY=null
        OTHER_SECRET=true
        API_PASSWORD=false
        APP_ONE_KEY=1
        APP_ZERO_KEY=0
        API_TOKEN=
        APP_NAME=Laravel
        Text;

    // Allow an extra exists() call when checking for an existing encrypted file
    $this->filesystem->shouldReceive('exists')
        ->andReturn(true, false, false)
        ->shouldReceive('get')
        ->andReturn($contents)
        ->shouldReceive('put')
        ->withArgs(function ($file, $contents) {
            // Ensure safe values are left as-is (not encrypted)
            $this->assertStringContainsString('APP_KEY=null' . PHP_EOL, $contents);
            $this->assertStringContainsString('OTHER_SECRET=true' . PHP_EOL, $contents);
            $this->assertStringContainsString('API_PASSWORD=false' . PHP_EOL, $contents);
            $this->assertStringContainsString('APP_ONE_KEY=1' . PHP_EOL, $contents);
            $this->assertStringContainsString('APP_ZERO_KEY=0' . PHP_EOL, $contents);
            $this->assertStringContainsString('API_TOKEN=' . PHP_EOL, $contents);

            // Sanity check that non-matching keys are preserved too
            $this->assertStringContainsString('APP_NAME=Laravel', $contents);

            return true;
        })
        ->andReturnTrue();

    $this->artisan('env:encrypt', ['--env' => 'production', '--key' => 'abcdefghijklmnopabcdefghijklmnop', '--only-values' => true])
        ->expectsOutputToContain('Environment successfully encrypted.')
        ->assertExitCode(0);
});
