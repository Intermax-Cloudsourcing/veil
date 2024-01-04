<?php

declare(strict_types=1);

use Illuminate\Encryption\Encrypter;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Facades\File;
use Mockery as m;

beforeEach(function () {
    $this->filesystem = m::spy(Filesystem::class);
    $this->filesystem->shouldReceive('put')
        ->andReturn(true);
    File::swap($this->filesystem);
});

it('decrypts an encrypted environment where only values are encrypted', function () {
    $contents = <<<'Text'
        APP_NAME=Laravel
        APP_ENV=local
        APP_DEBUG=true
        APP_URL=http://localhost
        Text;

    $encrypter = new Encrypter('abcdefghijklmnopabcdefghijklmnop', 'AES-256-CBC');

    $encryptedContents = <<<TEXT
        APP_NAME={$encrypter->encrypt('Laravel')}
        APP_ENV={$encrypter->encrypt('local')}
        APP_DEBUG={$encrypter->encrypt('true')}
        APP_URL={$encrypter->encrypt('http://localhost')}
        TEXT;

    $this->filesystem->shouldReceive('exists')
        ->once()
        ->andReturn(true)
        ->shouldReceive('exists')
        ->once()
        ->andReturn(false)
        ->shouldReceive('get')
        ->once()
        ->andReturn($encryptedContents);

    $this->artisan('env:decrypt', ['--env' => 'production', '--key' => 'abcdefghijklmnopabcdefghijklmnop', '--filename' => '.env', '--path' => '/tmp', '--only-values' => true])
        ->expectsOutputToContain('Environment successfully decrypted.')
        ->assertExitCode(0);

    $this->filesystem->shouldHaveReceived('put')
        ->with('/tmp'.DIRECTORY_SEPARATOR.'.env', $contents);
});
