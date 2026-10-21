<?php

namespace App\Actions\Account;

use App\Models\User;
use App\Services\PrivateStorage;
use Illuminate\Http\UploadedFile;
use Throwable;

class UpdateProfile
{
    /** @param array{name: string, avatar?: UploadedFile|null} $attributes */
    public function handle(User $user, array $attributes): void
    {
        $oldAvatar = $user->avatar_path;
        $newAvatar = isset($attributes['avatar']) ? $attributes['avatar']->store('avatars', PrivateStorage::name()) : null;
        if ($newAvatar === false) {
            abort(500, 'The avatar could not be stored. Please try again.');
        }

        try {
            $user->name = $attributes['name'];
            if ($newAvatar !== null) {
                $user->avatar_path = $newAvatar;
            }
            $user->save();
        } catch (Throwable $exception) {
            if ($newAvatar !== null) {
                PrivateStorage::disk()->delete($newAvatar);
            }
            throw $exception;
        }

        if ($newAvatar !== null && $oldAvatar !== null) {
            PrivateStorage::disk()->delete($oldAvatar);
        }
    }
}
