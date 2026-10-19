<?php

namespace App\Notifications;

use App\Models\User;
use Carbon\CarbonImmutable;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldBeEncrypted;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class AccountDeletionRequested extends Notification implements ShouldBeEncrypted, ShouldQueue
{
    use Queueable;

    public function __construct(public readonly string $dueAt)
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
        return $notifiable instanceof User && $notifiable->deletionCancellable()
            && $notifiable->deletion_due_at?->toISOString() === $this->dueAt;
    }

    public function toMail(object $notifiable): MailMessage
    {
        return (new MailMessage)->subject('Your Aether account is scheduled for deletion')
            ->line('Your Aether access has been disabled. Your sessions, tokens and saved approvals have been revoked.')
            ->line('Your personal account data will be erased on or after '.CarbonImmutable::parse($this->dueAt)->utc()->format('Y-m-d H:i:s').' UTC.')
            ->line('To cancel before that deadline, sign in with your password and existing two-factor authentication, then explicitly cancel deletion.')
            ->action('Review deletion', url('/account/deletion/pending'))
            ->line('Aether retains a minimal anonymized account reference and audit history. Independent applications retain their own data and sessions.');
    }
}
