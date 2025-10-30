<?php

declare(strict_types=1);

namespace Intermax\Veil\Console;

use Exception;
use Illuminate\Contracts\Encryption\DecryptException;
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
                    {--only=**_KEY,*_SECRET,*_PASSWORD,*_TOKEN : Encrypt only variables that match provided comma-separated patterns, by default values with *_KEY, *_SECRET, *_TOKEN and *_PASSWORD will be encrypted}
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
                $encryptedContents = $this->encryptValues($contents, $encrypter, $this->files->get($encryptedFile));
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

    protected function encryptValues(string $contents, Encrypter $encrypter, ?string $existingEncryptedContents): string
    {
        /** @var array<int, string> $only */
        $only = $this->option('only');
        $existingEncryptedLines = Str::of($existingEncryptedContents ?? '')->explode(PHP_EOL);

        return implode(PHP_EOL, collect(explode(PHP_EOL, $contents))->map(function (string $line) use ($encrypter, $only, $existingEncryptedLines) {
            $line = Str::of($line);

            if (! $line->contains('=')) {
                return $line;
            }

            if (! $this->option('all') && $only !== null && ! $line->before('=')->is($only)) {
                return $line;
            }

            $key = $line->before('=');
            $value = $line->after('=');

            $existingEncryptedLine = $existingEncryptedLines->first(fn (string $encryptedLine) => Str::of($encryptedLine)->before('=')->exactly($key));
            $existingEncryptedValue = $existingEncryptedLine ? Str::of($existingEncryptedLine)->after('=') : null;
            $existingValue = null;

            try {
                $existingValue = $existingEncryptedValue ? $encrypter->decrypt($existingEncryptedValue->toString()) : null;
            } catch (DecryptException $exception) {
                // The existing value could not be decrypted, most likely because it was a non-encrypted value before (null, true, false, blank, or just plain text)
            }

            /**
             * Prevent rotating already encrypted values to improve source control diffs
             */
            if ($value->exactly($existingValue)) {
                return $existingEncryptedLine;
            }

            /**
             * Skip blank, null, true, false values
             */
            if (blank($value) || $value->exactly('null') || $value->exactly('true') || $value->exactly('false')) {
                return $line;
            }

            /**
             * Encrypt and return updated line
             */
            return $line->before('=')
                ->append('=')
                ->append(
                    $line->after('=')
                        ->pipe(fn (Stringable $value) => $encrypter->encrypt($value->toString()))
                );
        })->toArray());
    }
}
