<?php

/*
|--------------------------------------------------------------------------
| Aturan Risiko
|--------------------------------------------------------------------------
|
| Nilai diambil dari sheet Peta Risiko pada template Risk Register
| (RiskMatrix F6:J10 dan RiskLevel F15:J19). Baris = kemungkinan 1..5,
| kolom = dampak 1..5.
|
*/

return [

    'impact_labels' => [
        1 => 'Tidak Signifikan',
        2 => 'Kurang Signifikan',
        3 => 'Cukup Signifikan',
        4 => 'Signifikan',
        5 => 'Sangat Signifikan',
    ],

    'likelihood_labels' => [
        1 => 'Hampir Tidak Terjadi',
        2 => 'Jarang Terjadi',
        3 => 'Kadang-Kadang Terjadi',
        4 => 'Sering Terjadi',
        5 => 'Hampir Pasti Terjadi',
    ],

    'matrix' => [
        1 => [1 => 1, 2 => 3, 3 => 5, 4 => 8, 5 => 20],
        2 => [1 => 2, 2 => 7, 3 => 11, 4 => 13, 5 => 21],
        3 => [1 => 4, 2 => 10, 3 => 14, 4 => 17, 5 => 22],
        4 => [1 => 6, 2 => 12, 3 => 16, 4 => 19, 5 => 24],
        5 => [1 => 9, 2 => 15, 3 => 18, 4 => 23, 5 => 25],
    ],

    'levels' => [
        1 => [1 => 'Sangat Rendah', 2 => 'Rendah', 3 => 'Sedang', 4 => 'Sedang', 5 => 'Tinggi'],
        2 => [1 => 'Sangat Rendah', 2 => 'Rendah', 3 => 'Sedang', 4 => 'Sedang', 5 => 'Sangat Tinggi'],
        3 => [1 => 'Sangat Rendah', 2 => 'Rendah', 3 => 'Sedang', 4 => 'Tinggi', 5 => 'Sangat Tinggi'],
        4 => [1 => 'Rendah', 2 => 'Sedang', 3 => 'Tinggi', 4 => 'Tinggi', 5 => 'Sangat Tinggi'],
        5 => [1 => 'Rendah', 2 => 'Sedang', 3 => 'Tinggi', 4 => 'Sangat Tinggi', 5 => 'Sangat Tinggi'],
    ],

    // IR sama dengan atau di atas nilai ini berstatus Not Acceptable (rumus template)
    'not_acceptable_threshold' => 11,

    'treatment_option' => 'Mitigasi Risiko',
    'risk_type' => 'Negatif',

    /*
    | Finding Nuclei di luar katalog (bagian 24.4)
    */
    'nuclei' => [
        'impact_by_severity' => ['critical' => 5, 'high' => 4, 'medium' => 3, 'low' => 2],
        'likelihood_default' => 3,
        'likelihood_kev' => 5,
        'category' => 'Ketidaksesuaian Pengelolaan Aplikasi',
        'threat' => 'Terjadi peretasan pada aplikasi',
        'vulnerability_cve' => 'Aplikasi tidak update',
        'vulnerability_default' => 'Adanya miss konfigurasi pada aplikasi',
        'impact_area' => 'Operasional dan Aset TIK',
        'output' => 'Kerawanan yang dilaporkan scanner telah ditutup dan tidak terdeteksi lagi pada pemeriksaan ulang.',
        'impact_description' => 'Kerawanan pada aplikasi berpotensi dimanfaatkan pihak yang tidak berwenang sehingga mengganggu keamanan dan layanan aplikasi.',
        'recommendation' => 'Tindak lanjuti temuan sesuai rekomendasi scanner, lakukan pembaruan atau perbaikan konfigurasi, lalu lakukan pemeriksaan ulang.',
        'additional_control' => 'Lakukan vulnerability assessment dan pembaruan perangkat lunak secara berkala.',
    ],

];
