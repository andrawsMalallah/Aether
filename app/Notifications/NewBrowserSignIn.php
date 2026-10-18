<?php

namespace App\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldBeEncrypted;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class NewBrowserSignIn extends Notification implements ShouldBeEncrypted, ShouldQueue
{
    use Queueable;

    public function __construct(
        public readonly string $browser,
        public readonly string $ipAddress,
        public readonly string $signedInAt,
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
        return (new MailMessage)
            ->subject('New browser sign-in to Aether')
            ->line('Your Aether account was signed in from a browser we do not recognize.')
            ->line('Browser: '.$this->browser)
            ->line('IP address: '.$this->ipAddress)
            ->line('Time: '.$this->signedInAt)
            ->line('Was this you? If so, no action is needed. Browser and device details are estimates.')
            ->action('Review active sessions', url('/account/sessions'))
            ->line('If this was not you, reset your password and revoke unfamiliar sessions.');
    }
}
