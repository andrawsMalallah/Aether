<?php

namespace App\Notifications;

use App\Enums\AccountExportStatus;
use App\Models\AccountExport;
use App\Models\User;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldBeEncrypted;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class AccountExportReady extends Notification implements ShouldBeEncrypted, ShouldQueue
{
    use Queueable;

    public function __construct(public readonly string $exportId)
    {
        $this->afterCommit();
    }

    /** @return list<string> */
    public function via(object $notifiable): array
    {
        return ['mail'];
    }

    public function shouldSend(object $notifiable, string $channel): bool
    {
        return $notifiable instanceof User && $notifiable->accountAvailable() && $notifiable->hasVerifiedEmail()
            && AccountExport::whereKey($this->exportId)->where('user_id', $notifiable->id)
                ->whereIn('status', [AccountExportStatus::Ready, AccountExportStatus::ReadyToNotify])->where('expires_at', '>', now())->exists();
    }

    public function toMail(object $notifiable): MailMessage
    {
        return (new MailMessage)->subject('Your Aether account export is ready')
            ->line('Your account data is ready to download as a JSON file. It expires 24 hours after preparation finishes.')
            ->line('Sign in and confirm your password to download it. This email does not contain your account data.')
            ->action('Review account exports', url('/account/export'))
            ->line('Keep the downloaded file private. If you did not request this export, review your account security.');
    }
}
