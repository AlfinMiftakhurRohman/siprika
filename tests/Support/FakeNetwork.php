<?php

namespace Tests\Support;

use App\Scanner\Network\DnsResolver;
use App\Scanner\Network\PortProber;
use App\Scanner\Network\TlsInspector;
use App\Scanner\Network\TlsReport;
use Carbon\CarbonImmutable;
use Closure;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use RuntimeException;
use Throwable;

/**
 * Pengganti akses jaringan scanner untuk test, supaya test tidak butuh internet.
 */
class FakeNetwork implements DnsResolver, PortProber, TlsInspector
{
    /** @var array<string, mixed> rute HTTP terakhir dari http() */
    private static array $routes = [];

    /** @var array<string, list<string>|Throwable|Closure(): list<string>> */
    public array $dns = [];

    /** @var list<int> */
    public array $openPorts = [80, 443];

    public TlsReport|Throwable|null $tls = null;

    /**
     * Hasil probe per versi. Nilai berupa list dipakai berurutan per percobaan, contoh ['error', 'rejected'].
     *
     * @var array<string, string|list<string>>
     */
    public array $protocols = ['TLSv1.0' => 'rejected', 'TLSv1.1' => 'rejected', 'TLSv1.2' => 'accepted', 'TLSv1.3' => 'accepted'];

    public function resolve(string $host): array
    {
        $result = $this->dns[$host] ?? ['93.184.216.34'];

        // Closure dipakai untuk mensimulasikan DNS yang berubah di antara permintaan (DNS rebinding)
        if ($result instanceof Closure) {
            $result = $result();
        }

        if ($result instanceof Throwable) {
            throw $result;
        }

        return $result;
    }

    public function isOpen(string $ip, int $port, float $timeout): bool
    {
        return in_array($port, $this->openPorts, true);
    }

    public function inspect(string $host, string $ip, int $port = 443): TlsReport
    {
        if ($this->tls instanceof Throwable) {
            throw $this->tls;
        }

        return $this->tls ?? self::validCertificate($host);
    }

    public function probeProtocol(string $host, string $ip, string $version, int $port = 443): string
    {
        $result = $this->protocols[$version] ?? 'rejected';

        if (is_array($result)) {
            return count($result) > 1 ? array_shift($this->protocols[$version]) : $result[0];
        }

        return $result;
    }

    /**
     * @param  array<string, mixed>  $overrides
     */
    public static function validCertificate(string $host, array $overrides = []): TlsReport
    {
        $values = $overrides + [
            'subject' => $host,
            'subjectAltNames' => [$host],
            'issuer' => 'R11, Let\'s Encrypt',
            'validFrom' => CarbonImmutable::now()->subDays(30),
            'validTo' => CarbonImmutable::now()->addDays(60),
            'selfSigned' => false,
            'chainLength' => 2,
            'protocol' => 'TLSv1.3',
            'cipher' => 'TLS_AES_256_GCM_SHA384',
            'verified' => true,
            'verifyError' => null,
        ];

        return new TlsReport(...$values);
    }

    /**
     * Pasang Http::fake berdasarkan peta URL => respons. URL yang tidak terdaftar menjawab 404.
     * Nilai string "refused" atau "timeout" mensimulasikan kegagalan koneksi.
     *
     * @param  array<string, mixed>  $routes
     */
    public static function http(array $routes): void
    {
        self::$routes = $routes;

        // Http::fake yang terdaftar lebih dulu selalu menang, jadi semua fake membaca rute terakhir:
        // pemanggilan http() berikutnya dalam satu test mengganti rute sebelumnya
        Http::fake(function (Request $request) {
            $routes = self::$routes;
            // https://host dan https://host/ adalah permintaan yang sama (GET /)
            $url = $request->url();
            $url = parse_url($url, PHP_URL_PATH) === null ? $url.'/' : $url;
            $response = $routes[$url] ?? Http::response('Not Found', 404);

            // Kunci berakhiran * mencocokkan awalan URL, contoh API ZAP; nilai Closure menerima permintaannya
            foreach ($routes as $pattern => $route) {
                if (! isset($routes[$url]) && str_ends_with($pattern, '*') && str_starts_with($url, rtrim($pattern, '*'))) {
                    $response = $route instanceof Closure ? $route($request) : $route;

                    break;
                }
            }

            return match ($response) {
                'refused' => Http::failedConnection('cURL error 7: Failed to connect: Connection refused')($request),
                'timeout' => Http::failedConnection('cURL error 28: Operation timed out')($request),
                default => $response,
            };
        });
    }

    public static function dnsFailure(): RuntimeException
    {
        return new RuntimeException('Permintaan DNS gagal.');
    }
}
