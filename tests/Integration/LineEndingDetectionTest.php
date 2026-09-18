<?php

declare(strict_types=1);

use Intermax\Veil\Concerns\LineEndingDetection;

$detector = new class
{
    use LineEndingDetection;

    public function detect(string $contents): string
    {
        return $this->detectLineEnding($contents);
    }
};

it('detects line endings of the given contents', function (string $contents, string $expected) use ($detector) {
    expect($detector->detect($contents))->toBe($expected);
})->with([
    'unix' => ["APP_NAME=Laravel\nAPP_ENV=local", "\n"],
    'windows' => ["APP_NAME=Laravel\r\nAPP_ENV=local", "\r\n"],
    'mixed, first occurrence windows' => ["APP_NAME=Laravel\r\nAPP_ENV=local\nAPP_DEBUG=true", "\r\n"],
    'single line' => ['APP_NAME=Laravel', "\n"],
    'empty' => ['', "\n"],
]);
