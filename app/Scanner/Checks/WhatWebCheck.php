<?php

namespace App\Scanner\Checks;

use App\Enums\ObservationStatus;
use App\Scanner\Fingerprint;
use App\Scanner\Parsers\WhatWebParser;
use App\Scanner\ScanContext;

/**
 * Technology fingerprinting tambahan dengan WhatWeb (aggression level 1, pasif).
 */
class WhatWebCheck extends ExternalToolCheck
{
    public function key(): string
    {
        return 'whatweb';
    }

    public function label(): string
    {
        return 'WhatWeb';
    }

    protected function tool(): string
    {
        return 'whatweb';
    }

    protected function envName(): string
    {
        return 'WHATWEB_PATH';
    }

    protected function execute(ScanContext $context): void
    {
        $this->inWorkDirectory(function (string $directory) use ($context) {
            $result = $this->tools->run('whatweb', [
                '--color=never', '--no-errors', '-a', '1',
                '--follow-redirect=never',
                '-U', (string) config('siprika.scan.user_agent'),
                '--log-json=whatweb.json',
                $context->reachableUrl(),
            ], $this->timeout($context), $directory);

            $file = $directory.DIRECTORY_SEPARATOR.'whatweb.json';
            $items = is_file($file) ? json_decode((string) file_get_contents($file), true) : null;

            if (! is_array($items)) {
                $this->observe($context, ObservationStatus::Error, $result->errorSummary());

                return;
            }

            $technologies = WhatWebParser::parse($items);
            $context->addTechnologies($technologies);

            $summary = $technologies === [] ? 'Tidak ada teknologi tambahan.' : Fingerprint::describe($technologies).'.';
            $this->observe($context, ObservationStatus::Info, $summary, ['technologies' => $technologies]);
        });
    }
}
