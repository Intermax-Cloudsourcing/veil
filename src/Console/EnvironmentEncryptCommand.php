<?php

declare(strict_types=1);

namespace Intermax\Veil\Console;

use Exception;
use Illuminate\Encryption\Encrypter;
use Illuminate\Foundation\Console\EnvironmentEncryptCommand as BaseEncryptCommand;
use Illuminate\Support\Str;
use Illuminate\Support\Stringable;

class EnvironmentEncryptCommand extends BaseEncryptCommand
{
    protected $signature = 'env:encrypt
                    {--key= : The encryption key}
                    {--cipher= : The encryption cipher}
                    {--env= : The environment to be encrypted}
                    {--force : Overwrite the existing encrypted environment file}
                    {--only-values : Encrypt only the values to keep the file readable}
                    {--only=**_KEY,*_KEYS,*_SECRET,*_PASSWORD,*_TOKEN : Encrypt only variables that match provided comma-separated patterns, by default values with *_KEY, *_SECRET, *_TOKEN and *_PASSWORD will be encrypted}
                    {--all : Ignore the --only flag and default patterns to encrypt all variables}';

    public function handle()
    {
        $cipher = $this->option('cipher') ?: 'AES-256-CBC';
        $key = $this->option('key');
        $keyPassed = $key !== null;
        $environmentFile = $this->option('env')
            ? base_path('.env').'.'.$this->option('env')
            : $this->laravel->environmentFilePath();
        $encryptedFile = $environmentFile.'.encrypted';
        if (! $keyPassed) {
            $key = Encrypter::generateKey($cipher);
        }
        if (! $this->files->exists($environmentFile)) {
            $this->components->error('Environment file not found.');

            return self::FAILURE;
        }

        if ($this->files->exists($encryptedFile) && ! $this->option('force')) {
            $this->components->error('Encrypted environment file already exists.');

            return self::FAILURE;
        }

        try {
            $encrypter = new Encrypter($this->parseKey($key), $cipher);

            $contents = $this->files->get($environmentFile);

            if ($this->option('only-values')) {
                $encryptedContents = $this->encryptValues($contents, $encrypter);
            } else {
                $encryptedContents = $encrypter->encrypt($contents);
            }

            $this->files->put(
                $encryptedFile,
                $encryptedContents
            );

        } catch (Exception $e) {
            $this->components->error($e->getMessage());

            return self::FAILURE;
        }

        $this->components->info('Environment successfully encrypted.');
        $this->components->twoColumnDetail('Key', $keyPassed ? $key : 'base64:'.base64_encode($key));
        $this->components->twoColumnDetail('Cipher', $cipher);
        $this->components->twoColumnDetail('Encrypted file', $encryptedFile);
        $this->newLine();

        return self::SUCCESS;
    }

    protected function encryptValues(string $contents, Encrypter $encrypter): string
    {
        /** @var array<int, string> $only */
        $only = $this->option('only');

        return implode(PHP_EOL, collect(explode(PHP_EOL, $contents))->map(function (string $line) use ($encrypter, $only) {
            $line = Str::of($line);

            if (! $line->contains('=')) {
                return $line;
            }

            if (! $this->option('all') && $only !== null && ! $line->before('=')->is($only)) {
                return $line;
            }

            return $line->before('=')
                ->append('=')
                ->append(
                    $line->after('=')
                        ->pipe(fn (Stringable $value) => $encrypter->encrypt($value->toString()))
                );
        })->toArray());
    }
}
