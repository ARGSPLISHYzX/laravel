<?php
namespace App\Http\Controllers;
use App\Jobs\GenerateReportJob;
use Illuminate\Http\Request;
class ReportController extends Controller
{
    public function generateAndSendReport(Request $request)
    {
        if (!auth()->check() || !auth()->user()->hasPermission('admin-access')) {
            return response()->json(['message' => 'Access denied: Only administrators can perform this action'], 403);
        }
        GenerateReportJob::dispatch();
        return response()->json(['message' => 'Report generation started'], 200);
    }
}