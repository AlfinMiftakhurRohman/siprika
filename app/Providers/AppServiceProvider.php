<?php

namespace App\Providers;

use App\Scanner\Network\DnsResolver;
use App\Scanner\Network\PortProber;
use App\Scanner\Network\SocketPortProber;
use App\Scanner\Network\StreamTlsInspector;
use App\Scanner\Network\SystemDnsResolver;
use App\Scanner\Network\TlsInspector;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        // Akses jaringan scanner, diganti versi palsu saat test
        $this->app->bind(DnsResolver::class, SystemDnsResolver::class);
        $this->app->bind(TlsInspector::class, StreamTlsInspector::class);
        $this->app->bind(PortProber::class, SocketPortProber::class);
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        //
    }
}
