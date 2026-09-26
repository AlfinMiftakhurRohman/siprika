<?php

namespace App\Scanner\Tools;

class ToolResult
{
    public function __construct(
        public readonly bool $successful,
        public readonly string $output,
        public readonly string $errorOutput,
        public readonly ?int $exitCode,
        public readonly bool $timedOut,
    ) {}

    public function errorSummary(): string
    {
        if ($this->timedOut) {
            return 'Tool melewati batas waktu.';
        }

        $message = trim($this->errorOutput) ?: trim($this->output);

        return 'Tool gagal (exit code '.($this->exitCode ?? '-').')'.($message !== '' ? ': '.mb_substr($message, 0, 300) : '.');
    }
}
