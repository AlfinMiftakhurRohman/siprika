<?php

namespace App\Scanner\Network;

class SocketPortProber implements PortProber
{
    public function isOpen(string $ip, int $port, float $timeout): bool
    {
        $address = str_contains($ip, ':') ? "[{$ip}]" : $ip;
        $socket = @stream_socket_client("tcp://{$address}:{$port}", $errno, $errstr, $timeout);

        if ($socket === false) {
            return false;
        }

        fclose($socket);

        return true;
    }
}
