<?php

namespace App\Http\Controllers;

use App\Models\ScanTarget;
use App\Risk\RiskRegisterExporter;
use Illuminate\Http\Request;
use Illuminate\View\View;
use Symfony\Component\HttpFoundation\BinaryFileResponse;

class ScanTargetController extends Controller
{
    public const TABS = [
        'overview' => 'Overview',
        'security' => 'Security Check',
        'findings' => 'Findings',
        'risk' => 'Risk Register',
        'coverage' => 'Coverage',
    ];

    public function show(Request $request, ScanTarget $scanTarget): View
    {
        // Nilai tab di luar daftar (termasuk bentuk array seperti ?tab[]=x) kembali ke Overview
        $tab = $request->query('tab');
        $tab = is_string($tab) && array_key_exists($tab, self::TABS) ? $tab : 'overview';

        $scanTarget->load(['batch', 'observations', 'findings.evidences', 'riskItems']);

        return view('targets.show', [
            'target' => $scanTarget,
            'tab' => $tab,
            'tabs' => self::TABS,
            'observations' => $scanTarget->observations->keyBy('check_key'),
        ]);
    }

    public function export(ScanTarget $scanTarget, RiskRegisterExporter $exporter): BinaryFileResponse
    {
        return $exporter->download($scanTarget->riskItems()->get(), "Risk Register SIPRIKA - {$scanTarget->host}.xlsx");
    }
}
