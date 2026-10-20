<?php

namespace App\Notifications;

use Carbon\CarbonImmutable;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldBeEncrypted;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;
use Illuminate\Support\Facades\URL;

class VerifyChangedEmail extends Notification implements ShouldBeEncrypted, ShouldQueue
{
    use Queueable;

    public function __construct(
        public readonly int $userId,
        public readonly string $email,
        public readonly CarbonImmutable $expiresAt,
    ) {
        $this->afterCommit();
    }

    /** @return list<string> */
    public function via(object $notifiable): array
    {
        return ['mail'];
    }

    public function toMail(object $notifiable): MailMessage
    {
        $url = URL::temporarySignedRoute('account.email.verify', $this->expiresAt, [
            'user' => $this->userId,
            'hash' => sha1($this->email),
        ]);

        return (new MailMessage)
            ->subject('Confirm your new Aether email address')
            ->line('Sign in with your current email address, then confirm this change.')
            ->action('Confirm email address', $url)
            ->line('This link expires in 60 minutes. Your current address stays active until you confirm.');
    }
}
