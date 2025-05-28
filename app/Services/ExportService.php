<?php
namespace App\Services;
use App\Models\User;
use App\Models\Role;
use PhpOffice\PhpSpreadsheet\Spreadsheet;
use PhpOffice\PhpSpreadsheet\Writer\Xlsx;
class ExportService
{
    public function exportUsers()
    {
        $users = User::all();
        $spreadsheet = new Spreadsheet();
        $sheet = $spreadsheet->getActiveSheet();
        $sheet->setCellValue('A1', 'ID');
        $sheet->setCellValue('B1', 'Username');
        $sheet->setCellValue('C1', 'Email');
        $sheet->setCellValue('D1', 'Birthday');
        $row = 2;
        foreach ($users as $user) {
            $sheet->setCellValue('A' . $row, $user->id);
            $sheet->setCellValue('B' . $row, $user->username);
            $sheet->setCellValue('C' . $row, $user->email);
            $sheet->setCellValue('D' . $row, $user->birthday);
            $row++;
        }
        $writer = new Xlsx($spreadsheet);
        $filePath = storage_path('app/exports/users.xlsx');
        $writer->save($filePath);
        return $filePath;
    }
    public function exportRoles()
    {
        $roles = Role::all();
        $spreadsheet = new Spreadsheet();
        $sheet = $spreadsheet->getActiveSheet();
        $sheet->setCellValue('A1', 'ID');
        $sheet->setCellValue('B1', 'Name');
        $sheet->setCellValue('C1', 'Code');
        $sheet->setCellValue('D1', 'Description');
        $row = 2;
        foreach ($roles as $role) {
            $sheet->setCellValue('A' . $row, $role->id);
            $sheet->setCellValue('B' . $row, $role->name);
            $sheet->setCellValue('C' . $row, $role->code);
            $sheet->setCellValue('D' . $row, $role->description);
            $row++;
        }
        $writer = new Xlsx($spreadsheet);
        $filePath = storage_path('app/exports/roles.xlsx');
        $writer->save($filePath);
        return $filePath;
    }
}