<?php

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Notification;

uses(RefreshDatabase::class);

it('rate limits login attempts', function (): void {
    for ($attempt = 0; $attempt < 5; $attempt++) {
        $this->post('/login', ['email' => 'unknown@example.com', 'password' => 'wrong'])->assertRedirect();
    }
    $this->post('/login', ['email' => 'unknown@example.com', 'password' => 'wrong'])->assertStatus(429);
});

it('rate limits registration by IP', function (): void {
    for ($attempt = 0; $attempt < 10; $attempt++) {
        $this->post('/register', [])->assertRedirect();
    }
    $this->post('/register', [])->assertStatus(429);
});

it('rate limits password reset requests by email independently of account existence', function (): void {
    for ($attempt = 0; $attempt < 3; $attempt++) {
        $this->post('/forgot-password', ['email' => 'unknown@example.com'])->assertRedirect();
    }
    $this->post('/forgot-password', ['email' => 'unknown@example.com'])->assertStatus(429);
});

it('rate limits password reset requests across different addresses on one IP', function (): void {
    for ($attempt = 0; $attempt < 10; $attempt++) {
        $this->post('/forgot-password', ['email' => 'unknown'.$attempt.'@example.com'])->assertRedirect();
    }
    $this->post('/forgot-password', ['email' => 'another@example.com'])->assertStatus(429);
});

it('rate limits password reset submissions', function (): void {
    for ($attempt = 0; $attempt < 5; $attempt++) {
        $this->post('/reset-password', [])->assertRedirect();
    }
    $this->post('/reset-password', [])->assertStatus(429);
});

it('rate limits verification email resends by user', function (): void {
    Notification::fake();
    $user = User::factory()->unverified()->create();
    $this->actingAs($user);
    for ($attempt = 0; $attempt < 6; $attempt++) {
        $this->post('/email/verification-notification')->assertRedirect();
    }
    $this->post('/email/verification-notification')->assertStatus(429);
});
