<?php
namespace App\Jobs;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Storage;
use App\Mail\ReportMail;
use App\Models\LogRequest;
use App\Models\ChangeLog;
use App\Models\User;
use Carbon\Carbon;
use PhpOffice\PhpSpreadsheet\IOFactory;
use PhpOffice\PhpSpreadsheet\Spreadsheet;
class GenerateReportJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;
    public function handle()
    {
        Log::info('Report generation started');
        try {
            $hours = config('app.report_interval_hours', 24);
            $startTime = Carbon::now()->subHours($hours);
            $methodRatings = $this->getMethodRatings($startTime);
            $entityRatings = $this->getEntityRatings($startTime);
            $userRatings = $this->getUserRatings($startTime);
            $reportData = [
                'type' => 'System Report',
                'generated_at' => now()->toDateTimeString(),
                'method_ratings' => $methodRatings,
                'entity_ratings' => $entityRatings,
                'user_ratings' => $userRatings,
            ];
            Storage::makeDirectory('reports');
            $fileName = 'report_' . now()->format('Ymd_His') . '.xlsx';
            $filePath = storage_path('app/reports/' . $fileName);
            $this->generateReportFile($reportData, $filePath);
            $this->sendReportToAdmins($filePath, $fileName);
            if (file_exists($filePath)) {
                unlink($filePath);
            }
            Log::info('Report generation completed');
        } catch (\Exception $e) {
            Log::error('Error during report generation: ' . $e->getMessage());
        }
    }
    private function getMethodRatings(Carbon $startTime): array
    {
        return LogRequest::where('created_at', '>=', $startTime)
            ->selectRaw('controller_method, COUNT(*) as count')
            ->groupBy('controller_method')
            ->orderByDesc('count')
            ->get()
            ->map(function ($item) use ($startTime) {
                return [
                    'method' => $item->controller_method,
                    'count' => $item->count,
                    'last_operation' => LogRequest::where('controller_method', $item->controller_method)
                        ->where('created_at', '>=', $startTime)
                        ->max('created_at'),
                ];
            })
            ->toArray();
    }
    private function getEntityRatings(Carbon $startTime): array
    {
        return ChangeLog::where('created_at', '>=', $startTime)
            ->selectRaw('entity_type, COUNT(*) as count')
            ->groupBy('entity_type')
            ->orderByDesc('count')
            ->get()
            ->map(function ($item) use ($startTime) {
                return [
                    'entity' => $item->entity_type,
                    'count' => $item->count,
                    'last_operation' => ChangeLog::where('entity_type', $item->entity_type)
                        ->where('created_at', '>=', $startTime)
                        ->max('created_at'),
                ];
            })
            ->toArray();
    }
    private function getUserRatings(Carbon $startTime): array
    {
        return User::withCount(['logRequests' => function ($query) use ($startTime) {
                $query->where('created_at', '>=', $startTime);
            }])
            ->orderByDesc('log_requests_count')
            ->get()
            ->map(function ($user) use ($startTime) {
                return [
                    'user' => $user->username,
                    'count' => $user->log_requests_count,
                    'last_operation' => LogRequest::where('user_id', $user->id)
                        ->where('created_at', '>=', $startTime)
                        ->max('created_at'),
                ];
            })
            ->toArray();
    }
    private function generateReportFile(array $data, string $filePath)
    {
        $spreadsheet = new Spreadsheet();
        $sheet = $spreadsheet->getActiveSheet();
        $sheet->setCellValue('A1', 'Type: ' . $data['type']);
        $sheet->setCellValue('A2', 'Generated At: ' . $data['generated_at']);
        $row = $this->writeSection($sheet, 'Method Ratings', ['Method', 'Count', 'Last Operation'], $data['method_ratings'], 4);
        $row = $this->writeSection($sheet, 'Entity Ratings', ['Entity', 'Count', 'Last Operation'], $data['entity_ratings'], $row + 2);
        $this->writeSection($sheet, 'User Ratings', ['User', 'Count', 'Last Operation'], $data['user_ratings'], $row + 2);
        $writer = IOFactory::createWriter($spreadsheet, 'Xlsx');
        $writer->save($filePath);
        if (file_exists($filePath)) {
            Log::info("File successfully created: $filePath");
        } else {
            Log::error("Failed to create file: $filePath");
        }
    }
    private function writeSection($sheet, string $title, array $headers, array $data, int $startRow): int
    {
        $sheet->setCellValue("A$startRow", $title);
        $sheet->fromArray($headers, null, "A" . ($startRow + 1));
        $row = $startRow + 2;
        foreach ($data as $item) {
            $sheet->fromArray([$item['method'] ?? $item['entity'] ?? $item['user'], $item['count'], $item['last_operation']], null, "A$row");
            $row++;
        }
        return $row;
    }
    private function sendReportToAdmins(string $filePath, string $fileName)
    {
        if (!file_exists($filePath)) {
            Log::error("File not found: $filePath");
            return;
        }
        try {
            $email = 'artem.gvozdev.89@bk.ru';
            Mail::to($email)->send(new ReportMail($filePath, $fileName));
            Log::info("Report sent to $email");
            if (file_exists($filePath)) {
                unlink($filePath);
            }
        } catch (\Exception $e) {
            Log::error("Error sending report: " . $e->getMessage());
        }
    }
}