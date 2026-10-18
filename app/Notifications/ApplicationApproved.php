<?php

namespace App\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldBeEncrypted;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;
use Illuminate\Support\HtmlString;

class ApplicationApproved extends Notification implements ShouldBeEncrypted, ShouldQueue
{
    use Queueable;

    /** @param list<string> $permissions */
    public function __construct(
        public readonly string $applicationName,
        public readonly array $permissions,
        public readonly string $approvedAt,
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
        $message = (new MailMessage)
            ->subject('You approved an application in Aether')
            ->line('You allowed an application to use your Aether account.')
            // A raw HTML block with escaped text prevents developer-controlled names
            // becoming Markdown links, images or headings inside a security email.
            ->line(new HtmlString('<p>Application: '.e($this->applicationName).'</p>'))
            ->line('Permissions approved:');

        foreach ($this->permissions as $permission) {
            $message->line($permission);
        }

        return $message->line('Time: '.$this->approvedAt)
            ->action('Review connected apps', url('/account/connected-apps'))
            ->line('If this was not you, disconnect the application and review your account security.');
    }
}
