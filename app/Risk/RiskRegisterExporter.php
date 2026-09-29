<?php

namespace App\Risk;

use App\Models\RiskRegisterItem;
use DOMDocument;
use DOMElement;
use DOMXPath;
use Illuminate\Support\Collection;
use RuntimeException;
use Symfony\Component\HttpFoundation\BinaryFileResponse;
use ZipArchive;

/**
 * Mengisi sheet Perangkat Lunak pada template Risk Register (bagian 25 dan 28).
 *
 * File xlsx diubah langsung di level XML, bukan dibuka lalu disimpan ulang, supaya
 * format, rumus, dropdown, comment, gambar, external link, dan sheet lain tetap utuh.
 */
class RiskRegisterExporter
{
    private const MAIN_NS = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main';

    private const REL_NS = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships';

    /** Kolom yang berisi rumus template, tidak ditulis nilainya */
    private const FORMULA_COLUMNS = ['L', 'M', 'X', 'Y', 'AB', 'AC', 'AF', 'AG', 'AH'];

    private string $sheetName;

    private int $firstRow;

    private int $templateLastRow;

    private int $templateTotalRow;

    public function __construct()
    {
        $this->sheetName = (string) config('siprika.excel.sheet');
        $this->firstRow = (int) config('siprika.excel.first_row');
        $this->templateLastRow = $this->firstRow + (int) config('siprika.excel.template_rows') - 1;
        $this->templateTotalRow = $this->templateLastRow + 1;
    }

    /**
     * @param  Collection<int, RiskRegisterItem>  $items  urut sesuai nomor risiko
     */
    public function export(Collection $items, string $destination): void
    {
        $template = (string) config('siprika.excel.template');

        if (! is_file($template)) {
            throw new RuntimeException("Template Risk Register tidak ditemukan: {$template}");
        }

        if (! copy($template, $destination)) {
            throw new RuntimeException("Gagal menyalin template ke {$destination}");
        }

        $zip = new ZipArchive;

        if ($zip->open($destination) !== true) {
            throw new RuntimeException('Template Risk Register tidak dapat dibuka.');
        }

        try {
            $workbook = (string) $zip->getFromName('xl/workbook.xml');
            [$sheetIndex, $sheetPath] = $this->findSheet($zip, $workbook, $this->sheetName)
                ?? throw new RuntimeException("Sheet {$this->sheetName} tidak ada di template.");
            $summaryPath = $this->findSheet($zip, $workbook, (string) config('siprika.excel.summary_sheet'))[1] ?? null;

            // Baris data minimal sebanyak baris bawaan template supaya tetap bisa diisi manual
            $rowCount = max($items->count(), $this->templateTotalRow - $this->firstRow);
            $lastRow = $this->firstRow + $rowCount - 1;
            $totalRow = $lastRow + 1;

            $zip->addFromString($sheetPath, $this->rewriteSheet((string) $zip->getFromName($sheetPath), $items->values(), $lastRow, $totalRow));
            $this->updateOtherSheets($zip, $sheetPath, $summaryPath, $lastRow, $totalRow);
            $zip->addFromString('xl/workbook.xml', $this->updateWorkbook($workbook, $sheetIndex, $lastRow));
            $this->removeCalcChain($zip);
        } finally {
            $zip->close();
        }
    }

    /**
     * Export ke file sementara untuk diunduh. File dihapus setelah terkirim.
     *
     * @param  Collection<int, RiskRegisterItem>  $items
     */
    public function download(Collection $items, string $filename): BinaryFileResponse
    {
        // tempnam membuat file kosong tanpa ekstensi, dihapus supaya tidak menumpuk
        $base = tempnam(sys_get_temp_dir(), 'siprika');
        @unlink($base);
        $path = $base.'.xlsx';

        $this->export($items, $path);

        return response()->download($path, $filename)->deleteFileAfterSend();
    }

    /**
     * @return array{0: int, 1: string}|null indeks sheet (0-based) dan path XML-nya di dalam zip
     */
    private function findSheet(ZipArchive $zip, string $workbook, string $sheetName): ?array
    {
        $document = $this->load($workbook);
        $xpath = new DOMXPath($document);
        $xpath->registerNamespace('m', self::MAIN_NS);

        $relationId = null;
        $index = 0;

        foreach ($xpath->query('//m:sheets/m:sheet') as $position => $sheet) {
            /** @var DOMElement $sheet */
            if ($sheet->getAttribute('name') === $sheetName) {
                $relationId = $sheet->getAttributeNS(self::REL_NS, 'id');
                $index = $position;
            }
        }

        if ($relationId === null) {
            return null;
        }

        $relations = $this->load((string) $zip->getFromName('xl/_rels/workbook.xml.rels'));

        foreach ($relations->getElementsByTagName('Relationship') as $relation) {
            if ($relation->getAttribute('Id') === $relationId) {
                return [$index, 'xl/'.ltrim(str_replace('/xl/', '', $relation->getAttribute('Target')), '/')];
            }
        }

        throw new RuntimeException("Relasi sheet {$sheetName} tidak ditemukan.");
    }

    /**
     * @param  Collection<int, RiskRegisterItem>  $items
     */
    private function rewriteSheet(string $xml, Collection $items, int $lastRow, int $totalRow): string
    {
        $document = $this->load($xml);
        $xpath = new DOMXPath($document);
        $xpath->registerNamespace('m', self::MAIN_NS);

        $sheetData = $xpath->query('//m:sheetData')->item(0);
        $templateRow = $xpath->query("//m:sheetData/m:row[@r='{$this->firstRow}']")->item(0);
        $templateTotal = $xpath->query("//m:sheetData/m:row[@r='{$this->templateTotalRow}']")->item(0);

        if (! $templateRow instanceof DOMElement || ! $templateTotal instanceof DOMElement) {
            throw new RuntimeException('Struktur baris template Perangkat Lunak tidak sesuai.');
        }

        $rowCells = $this->templateCells($templateRow);
        $totalCells = $this->templateCells($templateTotal);
        $widths = $this->columnWidths($xpath);

        // Hapus baris contoh bawaan dan baris total lama
        foreach (iterator_to_array($xpath->query('//m:sheetData/m:row')) as $row) {
            /** @var DOMElement $row */
            if ((int) $row->getAttribute('r') >= $this->firstRow) {
                $sheetData->removeChild($row);
            }
        }

        for ($row = $this->firstRow; $row <= $lastRow; $row++) {
            $item = $items->get($row - $this->firstRow);
            $values = $item !== null ? RiskRegisterSheet::values($item, $row - $this->firstRow + 1) : [];
            $sheetData->appendChild($this->buildRow($document, $templateRow, $rowCells, $row, $values, $widths,
                fn (string $formula) => $this->shiftRow($formula, $this->firstRow, $row)));
        }

        $sheetData->appendChild($this->buildRow($document, $templateTotal, $totalCells, $totalRow, [], [],
            fn (string $formula) => $this->translateTotals($formula, $lastRow, $totalRow)));

        $dimension = $xpath->query('//m:dimension')->item(0);

        if ($dimension instanceof DOMElement) {
            $dimension->setAttribute('ref', preg_replace('/\d+$/', (string) $totalRow, $dimension->getAttribute('ref')));
        }

        // Perluas dropdown ke semua baris baru
        foreach ($xpath->query('//m:dataValidations/m:dataValidation') as $validation) {
            /** @var DOMElement $validation */
            $validation->setAttribute('sqref', $this->extendRanges($validation->getAttribute('sqref'), $lastRow));
        }

        foreach ($xpath->query('//m:rowBreaks/m:brk') as $break) {
            /** @var DOMElement $break */
            if ((int) $break->getAttribute('id') === $this->templateLastRow) {
                $break->setAttribute('id', (string) $lastRow);
            }
        }

        return $document->saveXML();
    }

    /**
     * Gaya dan rumus setiap sel pada baris template.
     *
     * @return array<string, array{style: string|null, formula: string|null}>
     */
    private function templateCells(DOMElement $row): array
    {
        $cells = [];

        foreach ($row->getElementsByTagNameNS(self::MAIN_NS, 'c') as $cell) {
            $column = preg_replace('/\d+$/', '', $cell->getAttribute('r'));
            $formula = $cell->getElementsByTagNameNS(self::MAIN_NS, 'f')->item(0);

            $cells[$column] = [
                'style' => $cell->hasAttribute('s') ? $cell->getAttribute('s') : null,
                'formula' => $formula !== null && $formula->textContent !== '' ? $formula->textContent : null,
            ];
        }

        return $cells;
    }

    /**
     * @param  array<string, array{style: string|null, formula: string|null}>  $cells
     * @param  array<string, string|int>  $values
     * @param  array<string, float>  $widths
     * @param  callable(string): string  $translate
     */
    private function buildRow(DOMDocument $document, DOMElement $template, array $cells, int $rowNumber, array $values, array $widths, callable $translate): DOMElement
    {
        /** @var DOMElement $row */
        $row = $template->cloneNode(false);
        $row->setAttribute('r', (string) $rowNumber);

        if ($widths !== []) {
            $row->setAttribute('ht', (string) $this->rowHeight($values, $widths));
            $row->setAttribute('customHeight', '1');
        }

        foreach ($cells as $column => $cell) {
            $element = $document->createElementNS(self::MAIN_NS, 'c');
            $element->setAttribute('r', $column.$rowNumber);

            if ($cell['style'] !== null) {
                $element->setAttribute('s', $cell['style']);
            }

            $value = $values[$column] ?? null;

            if ($cell['formula'] !== null && ($value === null || in_array($column, self::FORMULA_COLUMNS, true))) {
                $formula = $document->createElementNS(self::MAIN_NS, 'f');
                $formula->appendChild($document->createTextNode($translate($cell['formula'])));
                $element->appendChild($formula);
            } elseif (is_int($value)) {
                $element->appendChild($document->createElementNS(self::MAIN_NS, 'v', (string) $value));
            } elseif (is_string($value) && $value !== '') {
                $element->setAttribute('t', 'inlineStr');
                $inline = $document->createElementNS(self::MAIN_NS, 'is');
                $text = $document->createElementNS(self::MAIN_NS, 't');
                $text->setAttribute('xml:space', 'preserve');
                $text->appendChild($document->createTextNode($value));
                $inline->appendChild($text);
                $element->appendChild($inline);
            }

            $row->appendChild($element);
        }

        return $row;
    }

    /**
     * Perkiraan tinggi baris supaya teks yang dibungkus terlihat.
     *
     * @param  array<string, string|int>  $values
     * @param  array<string, float>  $widths
     */
    private function rowHeight(array $values, array $widths): float
    {
        $lines = 2;

        foreach ($values as $column => $value) {
            if (! is_string($value) || $value === '') {
                continue;
            }

            $perLine = max(8, (int) floor(($widths[$column] ?? 10) * 1.05));
            $lines = max($lines, (int) ceil(mb_strlen($value) / $perLine));
        }

        return min(409, round($lines * 14.5 + 6, 1));
    }

    /**
     * Lebar kolom dari elemen <cols>.
     *
     * @return array<string, float>
     */
    private function columnWidths(DOMXPath $xpath): array
    {
        $widths = [];

        foreach ($xpath->query('//m:cols/m:col') as $col) {
            /** @var DOMElement $col */
            for ($i = (int) $col->getAttribute('min'); $i <= (int) $col->getAttribute('max'); $i++) {
                $widths[self::columnLetter($i)] = (float) $col->getAttribute('width');
            }
        }

        return $widths;
    }

    /**
     * Geser referensi sel baris template ke baris baru, contoh K7 menjadi K9.
     */
    private function shiftRow(string $formula, int $from, int $to): string
    {
        return $this->mapCellRows($formula, fn (int $row) => $row === $from ? $to : $row);
    }

    /**
     * Rumus baris total: akhir rentang SUM dan baris total mengikuti jumlah baris baru.
     */
    private function translateTotals(string $formula, int $lastRow, int $totalRow): string
    {
        return $this->mapCellRows($formula, fn (int $row) => match ($row) {
            $this->templateLastRow => $lastRow,
            $this->templateTotalRow => $totalRow,
            default => $row,
        });
    }

    /**
     * @param  callable(int): int  $map
     */
    private function mapCellRows(string $formula, callable $map): string
    {
        return $this->mapCellReferences($formula, fn (string $columnLock, string $column, string $rowLock, int $row) => $columnLock.$column.$rowLock.$map($row));
    }

    /**
     * Geser referensi relatif sejauh kolom dan baris tertentu, sama seperti Excel menyalin rumus.
     */
    private function shiftFormula(string $formula, int $columns, int $rows): string
    {
        return $this->mapCellReferences($formula, fn (string $columnLock, string $column, string $rowLock, int $row) => $columnLock
            .($columnLock === '' ? self::columnLetter(self::columnIndex($column) + $columns) : $column)
            .$rowLock.($rowLock === '' ? $row + $rows : $row));
    }

    /**
     * @param  callable(string, string, string, int): string  $map  menerima tanda $ kolom, kolom, tanda $ baris, dan baris
     */
    private function mapCellReferences(string $formula, callable $map): string
    {
        // Referensi sel di luar teks dalam tanda kutip dan nama sheet; nama range (RiskMatrix) tidak berangka sehingga tidak tersentuh
        $parts = preg_split('/("[^"]*"|\'[^\']*\')/', $formula, -1, PREG_SPLIT_DELIM_CAPTURE);

        foreach ($parts as $index => $part) {
            if (str_starts_with($part, '"') || str_starts_with($part, "'")) {
                continue;
            }

            $parts[$index] = preg_replace_callback(
                '/(?<![A-Za-z0-9_.])(\$?)([A-Z]{1,3})(\$?)(\d+)(?![\d(A-Za-z_])/',
                fn (array $m) => $map($m[1], $m[2], $m[3], (int) $m[4]),
                $part,
            );
        }

        return implode('', $parts);
    }

    private function extendRanges(string $sqref, int $lastRow): string
    {
        return implode(' ', array_map(function (string $range) use ($lastRow) {
            return preg_replace_callback(
                '/^([A-Z]{1,3})'.$this->firstRow.':([A-Z]{1,3})'.$this->templateLastRow.'$/',
                fn (array $m) => "{$m[1]}{$this->firstRow}:{$m[2]}{$lastRow}",
                $range,
            );
        }, explode(' ', $sqref)));
    }

    /**
     * Rumus di sheet lain (contoh Ringkasan) yang mengacu ke baris total ikut dipindahkan.
     */
    private function updateOtherSheets(ZipArchive $zip, string $sheetPath, ?string $summaryPath, int $lastRow, int $totalRow): void
    {
        $quotedName = preg_quote("'".str_replace("'", "''", $this->sheetName)."'", '/');

        for ($i = 0; $i < $zip->numFiles; $i++) {
            $name = (string) $zip->getNameIndex($i);

            if ($name === $sheetPath || ! preg_match('#^xl/worksheets/sheet\d+\.xml$#', $name)) {
                continue;
            }

            $xml = (string) $zip->getFromIndex($i);

            if (! str_contains($xml, htmlspecialchars("'".$this->sheetName."'", ENT_XML1 | ENT_NOQUOTES))) {
                continue;
            }

            $updated = preg_replace_callback('/(<f(?:\s[^>]*)?>)([^<]*)(<\/f>)/', function (array $m) use ($quotedName, $lastRow, $totalRow) {
                $formula = preg_replace_callback(
                    '/('.$quotedName.'!)(\$?[A-Z]{1,3}\$?\d+(?::\$?[A-Z]{1,3}\$?\d+)?)/',
                    fn (array $ref) => $ref[1].$this->translateTotals($ref[2], $lastRow, $totalRow),
                    $m[2],
                );

                return $m[1].$formula.$m[3];
            }, $xml);

            if ($name === $summaryPath) {
                $updated = $this->fixSummaryFormulas($updated, $this->sheetNames($zip), $this->sharedStrings($zip));
            }

            // Nilai tersimpan lama dihitung ulang Excel karena fullCalcOnLoad
            if ($updated !== $xml) {
                $zip->addFromString($name, $updated);
            }
        }
    }

    /**
     * Perbaikan kesalahan template pada baris aset sheet Ringkasan (baris yang mengambil total AI suatu sheet):
     * - rumus persentase Inherent dan Residual diganti sesuai config siprika.excel.summary_formulas, karena
     *   rumus bawaan membagi dengan jumlah Unacceptable;
     * - baris yang merujuk ke sheet lain dari labelnya (baris "SDM & Pihak Ketiga" merujuk 'Sarana Pendukung')
     *   diarahkan ke sheet sesuai label.
     *
     * @param  list<string>  $sheetNames
     * @param  list<string>  $sharedStrings
     */
    private function fixSummaryFormulas(string $xml, array $sheetNames, array $sharedStrings): string
    {
        $document = $this->load($xml);
        $xpath = new DOMXPath($document);
        $xpath->registerNamespace('m', self::MAIN_NS);

        foreach ($xpath->query('//m:sheetData/m:row') as $row) {
            /** @var DOMElement $row */
            $formulas = iterator_to_array($xpath->query('m:c/m:f', $row));
            $referenced = [];

            foreach ($formulas as $formula) {
                // Contoh 'Perangkat Lunak'!AI12; tanda kutip di nama sheet ditulis dua kali
                preg_match_all('/\'((?:[^\']|\'\')+)\'!\$?AI\$?\d/', $formula->textContent, $matches);
                array_push($referenced, ...array_map(fn (string $name) => str_replace("''", "'", $name), $matches[1]));
            }

            if ($referenced === []) {
                continue;
            }

            $rowNumber = $row->getAttribute('r');
            $label = $this->cellText($xpath, $row, "A{$rowNumber}", $sharedStrings);
            $wrongSheets = array_diff(array_unique($referenced), [$label]);

            if (in_array($label, $sheetNames, true) && $wrongSheets !== []) {
                foreach ($formulas as $formula) {
                    $text = $formula->textContent;

                    foreach ($wrongSheets as $wrong) {
                        $text = str_replace(self::quoteSheet($wrong).'!', self::quoteSheet($label).'!', $text);
                    }

                    $formula->nodeValue = '';
                    $formula->appendChild($document->createTextNode($text));
                }
            }

            foreach (config('siprika.excel.summary_formulas', []) as $column => $template) {
                $cell = $this->cellInRow($document, $xpath, $row, $column.$rowNumber);
                $this->unshareFormula($xpath, $cell);

                while ($cell->firstChild !== null) {
                    $cell->removeChild($cell->firstChild);
                }

                $cell->removeAttribute('t');
                $element = $document->createElementNS(self::MAIN_NS, 'f');
                $element->appendChild($document->createTextNode(str_replace('{row}', $rowNumber, $template)));
                $cell->appendChild($element);
            }
        }

        return $document->saveXML();
    }

    /**
     * Nama semua sheet di workbook.
     *
     * @return list<string>
     */
    private function sheetNames(ZipArchive $zip): array
    {
        $document = $this->load((string) $zip->getFromName('xl/workbook.xml'));
        $names = [];

        foreach ($document->getElementsByTagNameNS(self::MAIN_NS, 'sheet') as $sheet) {
            $names[] = $sheet->getAttribute('name');
        }

        return $names;
    }

    /**
     * Isi xl/sharedStrings.xml sesuai indeks.
     *
     * @return list<string>
     */
    private function sharedStrings(ZipArchive $zip): array
    {
        $xml = $zip->getFromName('xl/sharedStrings.xml');

        if ($xml === false) {
            return [];
        }

        $strings = [];

        foreach ($this->load($xml)->getElementsByTagNameNS(self::MAIN_NS, 'si') as $item) {
            $text = '';

            foreach ($item->getElementsByTagNameNS(self::MAIN_NS, 't') as $part) {
                $text .= $part->textContent;
            }

            $strings[] = $text;
        }

        return $strings;
    }

    /**
     * Teks sel (shared string, inline string, atau nilai), tanpa spasi di awal dan akhir.
     *
     * @param  list<string>  $sharedStrings
     */
    private function cellText(DOMXPath $xpath, DOMElement $row, string $reference, array $sharedStrings): string
    {
        $cell = $xpath->query("m:c[@r='{$reference}']", $row)->item(0);

        if (! $cell instanceof DOMElement) {
            return '';
        }

        $text = match ($cell->getAttribute('t')) {
            's' => $sharedStrings[(int) $xpath->query('m:v', $cell)->item(0)?->textContent] ?? '',
            'inlineStr' => implode('', array_map(fn ($t) => $t->textContent, iterator_to_array($xpath->query('m:is//m:t', $cell)))),
            default => (string) $xpath->query('m:v', $cell)->item(0)?->textContent,
        };

        return trim($text);
    }

    /**
     * Nama sheet dalam rumus, contoh 'SDM & Pihak Ketiga'.
     */
    private static function quoteSheet(string $name): string
    {
        return "'".str_replace("'", "''", $name)."'";
    }

    /**
     * Rumus shared (satu rumus induk dipakai beberapa sel) dijabarkan menjadi rumus biasa di setiap sel,
     * supaya satu sel di dalamnya bisa diganti tanpa merusak sel lain yang merujuk ke induknya.
     */
    private function unshareFormula(DOMXPath $xpath, DOMElement $cell): void
    {
        $formula = $xpath->query('m:f', $cell)->item(0);

        if (! $formula instanceof DOMElement || $formula->getAttribute('t') !== 'shared') {
            return;
        }

        $group = "//m:sheetData/m:row/m:c/m:f[@t='shared'][@si='{$formula->getAttribute('si')}']";
        $master = $xpath->query($group.'[@ref]')->item(0);

        if (! $master instanceof DOMElement) {
            return;
        }

        [$masterColumn, $masterRow] = self::splitCell($master->parentNode->getAttribute('r'));
        $masterFormula = $master->textContent;

        foreach (iterator_to_array($xpath->query($group)) as $member) {
            /** @var DOMElement $member */
            [$column, $row] = self::splitCell($member->parentNode->getAttribute('r'));

            while ($member->firstChild !== null) {
                $member->removeChild($member->firstChild);
            }

            $member->appendChild($member->ownerDocument->createTextNode(
                $this->shiftFormula($masterFormula, $column - $masterColumn, $row - $masterRow)));

            foreach (['t', 'si', 'ref'] as $attribute) {
                $member->removeAttribute($attribute);
            }
        }
    }

    /**
     * Sel pada baris, dibuat di posisi kolom yang benar jika belum ada.
     */
    private function cellInRow(DOMDocument $document, DOMXPath $xpath, DOMElement $row, string $reference): DOMElement
    {
        $existing = $xpath->query("m:c[@r='{$reference}']", $row)->item(0);

        if ($existing instanceof DOMElement) {
            return $existing;
        }

        $cell = $document->createElementNS(self::MAIN_NS, 'c');
        $cell->setAttribute('r', $reference);
        [$column] = self::splitCell($reference);

        foreach ($xpath->query('m:c', $row) as $sibling) {
            /** @var DOMElement $sibling */
            if (self::splitCell($sibling->getAttribute('r'))[0] > $column) {
                return $row->insertBefore($cell, $sibling);
            }
        }

        return $row->appendChild($cell);
    }

    private function updateWorkbook(string $xml, int $sheetIndex, int $lastRow): string
    {
        $document = $this->load($xml);
        $xpath = new DOMXPath($document);
        $xpath->registerNamespace('m', self::MAIN_NS);

        foreach ($xpath->query("//m:definedNames/m:definedName[@name='_xlnm.Print_Area'][@localSheetId='{$sheetIndex}']") as $definedName) {
            $definedName->nodeValue = preg_replace('/\$'.$this->templateLastRow.'$/', '\$'.$lastRow, $definedName->nodeValue);
        }

        // Paksa Excel menghitung ulang semua rumus saat file dibuka
        $calcPr = $xpath->query('//m:calcPr')->item(0);

        if ($calcPr instanceof DOMElement) {
            $calcPr->setAttribute('fullCalcOnLoad', '1');
        }

        return $document->saveXML();
    }

    /**
     * calcChain berisi daftar sel berumus lama; dihapus supaya Excel menyusunnya ulang tanpa pesan error.
     */
    private function removeCalcChain(ZipArchive $zip): void
    {
        if ($zip->locateName('xl/calcChain.xml') === false) {
            return;
        }

        $zip->deleteName('xl/calcChain.xml');

        $relations = (string) $zip->getFromName('xl/_rels/workbook.xml.rels');
        $zip->addFromString('xl/_rels/workbook.xml.rels', preg_replace('/<Relationship\b[^>]*Target="calcChain\.xml"[^>]*\/>/', '', $relations));

        $types = (string) $zip->getFromName('[Content_Types].xml');
        $zip->addFromString('[Content_Types].xml', preg_replace('/<Override\b[^>]*PartName="\/xl\/calcChain\.xml"[^>]*\/>/', '', $types));
    }

    private function load(string $xml): DOMDocument
    {
        $document = new DOMDocument;
        $document->preserveWhiteSpace = true;

        if (! $document->loadXML($xml)) {
            throw new RuntimeException('XML template tidak valid.');
        }

        return $document;
    }

    /**
     * Nomor kolom dan baris dari alamat sel, contoh "AB12" menjadi [28, 12].
     *
     * @return array{0: int, 1: int}
     */
    private static function splitCell(string $reference): array
    {
        preg_match('/^\$?([A-Z]{1,3})\$?(\d+)$/', $reference, $m);

        return [self::columnIndex($m[1]), (int) $m[2]];
    }

    public static function columnIndex(string $letter): int
    {
        $index = 0;

        foreach (str_split($letter) as $char) {
            $index = $index * 26 + ord($char) - 64;
        }

        return $index;
    }

    public static function columnLetter(int $index): string
    {
        $letter = '';

        while ($index > 0) {
            $index--;
            $letter = chr(65 + $index % 26).$letter;
            $index = intdiv($index, 26);
        }

        return $letter;
    }
}
