<?php

namespace App\Scanner\Network;

interface PortProber
{
    public function isOpen(string $ip, int $port, float $timeout): bool;
}
