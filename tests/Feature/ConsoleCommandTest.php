<?php

namespace Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class ConsoleCommandTest extends TestCase
{
    use RefreshDatabase;

    public function test_siprika_install_menampilkan_konfigurasi(): void
    {
        config([
            'siprika.allowed_domains' => ['jemberkab.go.id'],
            'siprika.tools.nuclei.command' => 'wsl -d Ubuntu -e nuclei',
            'siprika.ai.enabled' => true,
            'siprika.ai.server_command' => null,
        ]);

        $this->artisan('siprika:install')
            ->expectsOutputToContain('jemberkab.go.id')
            ->expectsOutputToContain('wsl -d Ubuntu -e nuclei')
            ->expectsOutputToContain('tidak dipakai (NOT ASSESSED)')
            ->expectsOutputToContain('jalankan llama-server sendiri')
            ->assertSuccessful();
    }
}
