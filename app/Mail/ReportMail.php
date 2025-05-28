<?php
namespace App\Mail;
use Illuminate\Bus\Queueable;
use Illuminate\Mail\Mailable;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;
class ReportMail extends Mailable
{
    use Queueable, SerializesModels;
    public $filePath;
    public $fileName;
    public function __construct($filePath, $fileName)
    {
        $this->filePath = $filePath;
        $this->fileName = $fileName;
    }
    public function build()
    {
        \Log::info("Attaching file: {$this->filePath}");
        if (!file_exists($this->filePath)) {
            \Log::error("File not found: {$this->filePath}");
            return $this->subject('System Report')->view('emails.report');
        }
        return $this->subject('System Report')
                    ->attach($this->filePath, [
                        'as' => $this->fileName,
                        'mime' => 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                    ])
                    ->view('emails.report');
    }
}