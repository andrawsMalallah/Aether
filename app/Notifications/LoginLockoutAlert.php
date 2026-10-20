<?php

namespace App\Notifications;

use App\Models\User;
use Carbon\CarbonImmutable;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldBeEncrypted;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class LoginLockoutAlert extends Notification implements ShouldBeEncrypted, ShouldQueue
{
    use Queueable;

    public int $tries = 3;

    public int $timeout = 30;

    public int $backoff = 30;

    public function __construct(
        public readonly string $email,
        public readonly CarbonImmutable $occurredAt,
    ) {
        $this->afterCommit();
    }

    /** @return list<string> */
    public function via(object $notifiable): array
    {
        return ['mail'];
    }

    public function shouldSend(object $notifiable, string $channel): bool
    {
        if (! $notifiable instanceof User || $this->occurredAt->isFuture() || $this->occurredAt->addMinutes(10)->isPast()) {
            return false;
        }
        $current = User::query()->select(['id', 'email', 'email_verified_at', 'deletion_requested_at', 'anonymized_at'])->find($notifiable->id);

        return $current !== null && $current->accountAvailable() && $current->hasVerifiedEmail()
            && $current->email === $this->email && $notifiable->email === $this->email
            && $current->email_verified_at?->isAfter($this->occurredAt) === false;
    }

    public function toMail(object $notifiable): MailMessage
    {
        return (new MailMessage)
            ->subject('Aether sign-in attempts temporarily limited')
            ->line('Repeated sign-in attempts for your account were temporarily rate limited.')
            ->line('Time: '.$this->occurredAt->utc()->format('Y-m-d H:i:s').' UTC')
            ->line('If you were trying to sign in, wait before trying again.')
            ->action('Review account security', url('/account/security'))
            ->line('If you do not recognize these attempts, review your account security and consider resetting your password.')
            ->line('To limit repeat messages, these alerts are normally limited to one every 24 hours.');
    }
}
