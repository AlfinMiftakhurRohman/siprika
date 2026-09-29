<#
.SYNOPSIS
    Memeriksa file export Risk Register di Microsoft Excel (bagian 28 blueprint).

.DESCRIPTION
    Membuka file lewat COM Excel (read-only, tanpa memperbarui external link) lalu memeriksa:
    - file terbuka tanpa perbaikan (repair);
    - rumus L, M, X, Y, AB, AC, AF, AG, AH di sheet Perangkat Lunak terhitung tanpa error;
    - dropdown ada di setiap baris data;
    - sheet Ringkasan terhitung tanpa error dan baris Perangkat Lunak sama dengan baris total.
    Hasil ditulis sebagai JSON. Exit code 1 jika ada pemeriksaan yang gagal.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\check-excel.ps1 -Path "Risk Register SIPRIKA - Batch 3.xlsx" -ExpectedRows 6
#>
param(
    [Parameter(Mandatory = $true)][string]$Path,
    [int]$ExpectedRows = 0
)

$ErrorActionPreference = 'Stop'
$Path = (Resolve-Path $Path).Path
$repairLogsBefore = @(Get-ChildItem $env:TEMP -Filter 'error*.xml' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)

$excel = New-Object -ComObject Excel.Application
$excel.Visible = $false
$excel.DisplayAlerts = $false
$excel.AskToUpdateLinks = $false
$result = [ordered]@{}

try {
    # UpdateLinks=0 (jangan perbarui external link), ReadOnly=true
    $wb = $excel.Workbooks.Open($Path, 0, $true)
    $excel.CalculateFull()

    $repairLogsAfter = @(Get-ChildItem $env:TEMP -Filter 'error*.xml' -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-2) } | Select-Object -ExpandProperty FullName)
    $newRepairLogs = @($repairLogsAfter | Where-Object { $repairLogsBefore -notcontains $_ })
    $result.opened = $true
    $result.workbook_name = $wb.Name
    $result.repaired = ($newRepairLogs.Count -gt 0) -or ($wb.Name -match 'Repaired|Diperbaiki')
    if ($newRepairLogs.Count -gt 0) { $result.repair_log = (Get-Content $newRepairLogs[0] -Raw) }

    $ws = $wb.Worksheets.Item('Perangkat Lunak')
    $rows = @()
    $row = 7
    while ($true) {
        $riskNo = [string]$ws.Range("A$row").Text
        if ($riskNo -notmatch '^PL-\d+') { break }
        $rows += [ordered]@{
            row = $row
            risk_no = $riskNo
            asset = [string]$ws.Range("C$row").Text
            impact = [string]$ws.Range("J$row").Text
            likelihood = [string]$ws.Range("K$row").Text
            ir = [string]$ws.Range("L$row").Text
            level = [string]$ws.Range("M$row").Text
            status = [string]$ws.Range("AF$row").Text
            decision = [string]$ws.Range("N$row").Text
            priority = [string]$ws.Range("O$row").Text
            option = [string]$ws.Range("P$row").Text
            control = [string]$ws.Range("I$row").Text
            residual = [string]$ws.Range("U$row").Text
            residual_impact = [string]$ws.Range("V$row").Text
            residual_likelihood = [string]$ws.Range("W$row").Text
            rr = [string]$ws.Range("X$row").Text
            rr_status = [string]$ws.Range("Y$row").Text
            empty_S_T_AA = ([string]$ws.Range("S$row").Text + [string]$ws.Range("T$row").Text + [string]$ws.Range("AA$row").Text) -eq ''
            validation_V = $ws.Range("V$row").Validation.Type
            validation_W = $ws.Range("W$row").Validation.Type
            validation_K = $ws.Range("K$row").Validation.Type
            validation_J = $ws.Range("J$row").Validation.Type
            validation_F = $ws.Range("F$row").Validation.Type
            validation_P = $ws.Range("P$row").Validation.Type
        }
        $row++
    }
    $result.data_rows = $rows.Count
    $result.rows = $rows
    $totalRow = [Math]::Max($row, 12)
    # Baris total berada tepat di bawah baris terakhir (minimal baris 12)
    for ($r = $row; $r -le $row + 6; $r++) {
        if ([string]$ws.Range("AI$r").Formula -like '=SUM(*') { $totalRow = $r; break }
    }
    $result.total_row = $totalRow
    $result.total_formula_AG = [string]$ws.Range("AG$totalRow").Formula
    $result.total_AI = $ws.Range("AI$totalRow").Value2
    $result.total_AG_acceptable = $ws.Range("AG$totalRow").Value2
    $result.total_AH_not_acceptable = $ws.Range("AH$totalRow").Value2

    $summary = $wb.Worksheets.Item('Ringkasan')
    $result.ringkasan_B11_formula = [string]$summary.Range('B11').Formula
    $result.ringkasan_B11 = [string]$summary.Range('B11').Text
    $summaryRows = @()
    foreach ($r in 10..14) {
        $summaryRows += [ordered]@{
            row = $r
            B = [string]$summary.Range("B$r").Text; C = [string]$summary.Range("C$r").Text; D = [string]$summary.Range("D$r").Text
            E = [string]$summary.Range("E$r").Text; E_formula = [string]$summary.Range("E$r").Formula
            F = [string]$summary.Range("F$r").Text; G = [string]$summary.Range("G$r").Text
            H = [string]$summary.Range("H$r").Text; H_formula = [string]$summary.Range("H$r").Formula
        }
    }
    $result.ringkasan = $summaryRows
    $result.total_AB_residual_acceptable = $ws.Range("AB$totalRow").Value2
    $result.total_AC_residual_not_acceptable = $ws.Range("AC$totalRow").Value2

    # Nilai error pada kolom rumus di baris data
    $errors = @()
    foreach ($r in $rows) {
        foreach ($col in @('L', 'M', 'X', 'Y', 'AB', 'AC', 'AF', 'AG', 'AH')) {
            $text = [string]$ws.Range("$col$($r.row)").Text
            if ($text -match '^#') { $errors += "$col$($r.row)=$text" }
        }
    }
    $result.formula_errors = $errors
    $result.expected_rows_ok = ($ExpectedRows -eq 0) -or ($rows.Count -eq $ExpectedRows)

    # Ringkasan: tanpa nilai error, dan baris Perangkat Lunak sama dengan baris total sheet Perangkat Lunak
    $summaryErrors = @()
    foreach ($r in $summaryRows) {
        foreach ($col in @('B', 'C', 'D', 'E', 'F', 'G', 'H')) {
            if ($r[$col] -match '^#') { $summaryErrors += "$col$($r.row)=$($r[$col])" }
        }
    }
    $result.summary_errors = $summaryErrors
    $result.summary_matches_totals = ([double]$summary.Range('B11').Value2 -eq [double]$result.total_AI) `
        -and ([double]$summary.Range('F11').Value2 -eq [double]$result.total_AB_residual_acceptable) `
        -and ([double]$summary.Range('G11').Value2 -eq [double]$result.total_AC_residual_not_acceptable)

    $dropdownMissing = @($rows | Where-Object { $_.validation_J -eq $null -or $_.validation_K -eq $null -or $_.validation_V -eq $null -or $_.validation_W -eq $null })
    $result.dropdown_ok = $dropdownMissing.Count -eq 0

    $wb.Close($false)
}
catch {
    $result.opened = $false
    $result.error = $_.Exception.Message
}
finally {
    $excel.Quit()
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($excel) | Out-Null
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
}

$result.ok = [bool]($result.opened -and -not $result.repaired -and $result.formula_errors.Count -eq 0 `
    -and $result.summary_errors.Count -eq 0 -and $result.summary_matches_totals -and $result.dropdown_ok -and $result.expected_rows_ok)

$result | ConvertTo-Json -Depth 5

if (-not $result.ok) {
    exit 1
}
