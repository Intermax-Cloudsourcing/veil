<?php

declare(strict_types=1);

namespace Intermax\Veil\Concerns;

trait LineEndingDetection
{
    /**
     * @return non-empty-string
     */
    protected function detectLineEnding(string $contents): string
    {
        return str_contains($contents, "\r\n") ? "\r\n" : "\n";
    }
}
