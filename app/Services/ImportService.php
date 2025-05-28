<?php
namespace App\Services;
use App\Models\User;
use App\Models\Role;
use PhpOffice\PhpSpreadsheet\IOFactory;
use Illuminate\Support\Facades\DB;
class ImportService
{
    public function importUsers($filePath, $mode)
    {
        $spreadsheet = IOFactory::load($filePath);
        $sheet = $spreadsheet->getActiveSheet();
        $rows = $sheet->toArray();
        array_shift($rows);
        $results = [];
        DB::beginTransaction();
        try {
            foreach ($rows as $index => $row) {
                $id = $row[0];
                $username = $row[1];
                $email = $row[2];
                $birthday = $row[3];
                $existingUser = User::find($id);
                if ($existingUser) {
                    if ($mode === 'update') {
                        $existingUser->update([
                            'username' => $username,
                            'email' => $email,
                            'birthday' => $birthday,
                        ]);
                        $results[] = "Запись №" . ($index + 1) . " успешно обновила запись с идентификатором №" . $id;
                    } else {
                        $results[] = "Запись №" . ($index + 1) . " содержит дубликат записи №" . $id . " по свойству ID";
                    }
                } else {
                    User::create([
                        'id' => $id,
                        'username' => $username,
                        'email' => $email,
                        'password' => bcrypt('default_password'),
                        'birthday' => $birthday,
                    ]);
                    $results[] = "Запись №" . ($index + 1) . " успешно добавлена с идентификатором №" . $id;
                }
            }
            DB::commit();
        } catch (\Exception $e) {
            DB::rollBack();
            $results[] = "Запись №" . ($index + 1) . " не удалось добавить/обновить. Неизвестная ошибка.";
        }
        return $results;
    }
    public function importRoles($filePath, $mode)
    {
        $spreadsheet = IOFactory::load($filePath);
        $sheet = $spreadsheet->getActiveSheet();
        $rows = $sheet->toArray();
        array_shift($rows);
        $results = [];
        DB::beginTransaction();
        try {
            foreach ($rows as $index => $row) {
                $id = $row[0];
                $name = $row[1];
                $code = $row[2];
                $description = $row[3];
                $existingRole = Role::find($id);
                if ($existingRole) {
                    if ($mode === 'update') {
                        $existingRole->update([
                            'name' => $name,
                            'code' => $code,
                            'description' => $description,
                        ]);
                        $results[] = "Запись №" . ($index + 1) . " успешно обновила запись с идентификатором №" . $id;
                    } else {
                        $results[] = "Запись №" . ($index + 1) . " содержит дубликат записи №" . $id . " по свойству ID";
                    }
                } else {
                    Role::create([
                        'id' => $id,
                        'name' => $name,
                        'code' => $code,
                        'description' => $description,
                    ]);
                    $results[] = "Запись №" . ($index + 1) . " успешно добавлена с идентификатором №" . $id;
                }
            }
            DB::commit();
        } catch (\Exception $e) {
            DB::rollBack();
            $results[] = "Запись №" . ($index + 1) . " не удалось добавить/обновить. Неизвестная ошибка.";
        }
        return $results;
    }
}