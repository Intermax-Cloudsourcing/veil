<?php

declare(strict_types=1);

namespace Intermax\Veil\Console;

use Exception;
use Illuminate\Encryption\Encrypter;
use Illuminate\Foundation\Console\EnvironmentDecryptCommand as BaseDecryptCommand;
use Illuminate\Support\Env;
use Illuminate\Support\Str;
use Illuminate\Support\Stringable;

class EnvironmentDecryptCommand extends BaseDecryptCommand
{
    protected $signature = 'env:decrypt
                    {--key= : The encryption key}
                    {--cipher= : The encryption cipher}
                    {--env= : The environment to be decrypted}
                    {--force : Overwrite the existing environment file}
                    {--path= : Path to write the decrypted file}
                    {--filename= : Filename of the decrypted file}
                    {--only-values : Enable if the encrypted file was encrypted with the same flag}';

    public function handle()
    {
        $key = $this->option('key') ?: Env::get('LARAVEL_ENV_ENCRYPTION_KEY');

        if (! $key) {
            $this->components->error('A decryption key is required.');

            return self::FAILURE;
        }

        $cipher = $this->option('cipher') ?: 'AES-256-CBC';
        $key = $this->parseKey($key);
        $encryptedFile = ($this->option('env')
                ? base_path('.env').'.'.$this->option('env')
                : $this->laravel->environmentFilePath()).'.encrypted';

        $outputFile = $this->outputFilePath();

        if (Str::endsWith($outputFile, '.encrypted')) {
            $this->components->error('Invalid filename.');

            return self::FAILURE;
        }

        if (! $this->files->exists($encryptedFile)) {
            $this->components->error('Encrypted environment file not found.');

            return self::FAILURE;
        }

        if ($this->files->exists($outputFile) && ! $this->option('force')) {
            $this->components->error('Environment file already exists.');

            return self::FAILURE;
        }
        try {
            $encrypter = new Encrypter($key, $cipher);

            $contents = $this->files->get($encryptedFile);

            if ($this->option('only-values')) {
                $decryptedContents = $this->decryptValues($contents, $encrypter);
            } else {
                $decryptedContents = $encrypter->decrypt($contents);
            }

            $this->files->put(
                $outputFile,
                $decryptedContents
            );
        } catch (Exception $e) {
            $this->components->error($e->getMessage());

            return self::FAILURE;
        }
        $this->components->info('Environment successfully decrypted.');
        $this->components->twoColumnDetail('Decrypted file', $outputFile);
        $this->newLine();

        return self::SUCCESS;
    }

    protected function decryptValues(string $contents, Encrypter $encrypter): string
    {
        return implode(PHP_EOL, collect(explode(PHP_EOL, $contents))->map(function (string $line) use ($encrypter) {
            $line = Str::of($line);

            if (! $line->contains('=')) {
                return $line;
            }

            return $line->before('=')
                ->append('=')
                ->append(
                    $line->after('=')
                        ->pipe(fn (Stringable $value) => $encrypter->decrypt($value->toString()))
                );
        })->toArray());
    }
}
