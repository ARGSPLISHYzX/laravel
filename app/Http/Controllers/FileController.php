<?php
namespace App\Http\Controllers;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;
use Intervention\Image\ImageManager;
use App\Models\File;
use ZipArchive;
use App\Models\User;
use PhpOffice\PhpSpreadsheet\IOFactory;
use PhpOffice\PhpSpreadsheet\Spreadsheet;
class FileController extends Controller
{
    public function upload(Request $request)
    {
        $maxFileSize = (int) config('app.max_file_size');
        $request->validate([
            'photo' => [
                'required',
                'image',
                'max:' . $maxFileSize,
            ],
            'description' => 'nullable|string',
        ]);
        $user = auth()->user();
        $file = $request->file('photo');
        $allowedExtensions = ['jpg', 'jpeg', 'png', 'gif'];
        if (!in_array(strtolower($file->extension()), $allowedExtensions)) {
            return response()->json(['error' => 'Invalid file format'], 422);
        }
        $fileName = Str::uuid() . '.' . $file->extension();
        $filePath = $file->storeAs('originals', $fileName, 'originals');
        $avatarName = pathinfo($fileName, PATHINFO_FILENAME) . '_avatar.' . $file->extension();
        $avatarPath = storage_path('app/public/avatars/' . $avatarName);
        if (!file_exists(storage_path('app/public/avatars'))) {
            mkdir(storage_path('app/public/avatars'), 0755, true);
        }
        try {
            $manager = ImageManager::gd();
            $image = $manager->read($file)->resize(128, 128);
            $image->save($avatarPath);
        } catch (\Exception $e) {
            \Log::error('Error processing image: ' . $e->getMessage());
            return response()->json(['error' => 'Failed to process image'], 500);
        }
        $fileModel = new File();
        $fileModel->user_id = $user->id;
        $fileModel->name = $file->getClientOriginalName();
        $fileModel->description = $request->input('description');
        $fileModel->format = $file->extension();
        $fileModel->size = $file->getSize();
        $fileModel->path = $filePath;
        $fileModel->avatar_path = 'avatars/' . $avatarName;
        $fileModel->save();
        $user->avatar_url = Storage::disk('public')->url('avatars/' . $avatarName);
        $user->save();
        return response()->json([
            'message' => 'File uploaded successfully',
            'file' => [
                'name' => $fileModel->name,
                'description' => $fileModel->description,
                'url' => Storage::disk('originals')->url($filePath),
                'avatar_url' => $user->avatar_url,
            ],
        ]);
    }
    public function delete()
    {
        $user = auth()->user();
        $file = $user->file;
        if ($file) {
            if (Storage::disk('originals')->exists($file->path)) {
                Storage::disk('originals')->delete($file->path);
            }
            if (Storage::disk('public')->exists($file->avatar_path)) {
                Storage::disk('public')->delete($file->avatar_path);
            }
            $file->delete();
            $user->avatar_url = null;
            $user->save();
        }
        return response()->json(['message' => 'File deleted successfully']);
    }
    public function download()
    {
        $user = auth()->user();
        $file = $user->file;
        if (!$file) {
            return response()->json(['error' => 'File not found'], 404);
        }
        $filePath = $file->path;
        if (!Storage::disk('originals')->exists($filePath)) {
            \Log::error("File does not exist: {$filePath}");
            return response()->json(['error' => 'File not found'], 404);
        }
        return Storage::disk('originals')->download($filePath, basename($filePath));
    }
    public function exportPhotos()
    {
        if (!auth()->user()->hasPermission('admin-access')) {
            return response()->json(['message' => 'Access denied: Only administrators can perform this action'], 403);
        }
        $zip = new ZipArchive();
        $zipFileName = storage_path('app/export/photos_' . now()->format('Ymd_His') . '.zip');
        if (!is_dir(storage_path('app/export'))) {
            mkdir(storage_path('app/export'), 0755, true);
        }
        if ($zip->open($zipFileName, ZipArchive::CREATE) !== true) {
            \Log::error("Failed to create ZIP archive: " . $zip->getStatusString());
            return response()->json(['message' => 'Failed to create ZIP archive'], 500);
        }
        $spreadsheet = new Spreadsheet();
        $sheet = $spreadsheet->getActiveSheet();
        $sheet->setCellValue('A1', 'User ID');
        $sheet->setCellValue('B1', 'Username');
        $sheet->setCellValue('C1', 'Upload Date');
        $sheet->setCellValue('D1', 'Filename');
        $sheet->setCellValue('E1', 'Server Path');
        $row = 2;
        foreach (User::with('file')->get() as $user) {
            if ($user->file) {
                $originalName = $user->username . '_' . $user->file->id . '.' . $user->file->format;
                $originalPath = storage_path('app/private/originals/' . ltrim($user->file->path, '/'));
                if (file_exists($originalPath)) {
                    $zip->addFile($originalPath, $originalName);
                } else {
                    \Log::error("Original file not found: $originalPath");
                    \Log::info("Database path: " . $user->file->path);
                }
                $avatarName = $user->username . '_' . $user->file->id . '_avatar.' . $user->file->format;
                $avatarPath = storage_path('app/public/' . ltrim($user->file->avatar_path, '/'));
                if (file_exists($avatarPath)) {
                    $zip->addFile($avatarPath, $avatarName);
                } else {
                    \Log::error("Avatar file not found: $avatarPath");
                }
                $sheet->setCellValue('A' . $row, $user->id);
                $sheet->setCellValue('B' . $row, $user->username);
                $sheet->setCellValue('C' . $row, $user->file->created_at);
                $sheet->setCellValue('D' . $row, $originalName);
                $sheet->setCellValue('E' . $row, $user->file->path);
                $row++;
            }
        }
        $excelFileName = 'photos_data.xlsx';
        $excelPath = storage_path('app/export/' . $excelFileName);
        $writer = IOFactory::createWriter($spreadsheet, 'Xlsx');
        $writer->save($excelPath);
        if (file_exists($excelPath)) {
            $zip->addFile($excelPath, $excelFileName);
        } else {
            \Log::error("Excel file not found: $excelPath");
        }
        $zip->close();
        if (file_exists($excelPath)) {
            unlink($excelPath);
        }
        if (file_exists($zipFileName)) {
            return response()->download($zipFileName)->deleteFileAfterSend(true);
        }
        return response()->json(['message' => 'Failed to generate archive'], 500);
    }
}