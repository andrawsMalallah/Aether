<?php

namespace App\Actions\Account;

use App\Models\User;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Storage;
use Throwable;

class UpdateProfile
{
    /** @param array{name: string, avatar?: UploadedFile|null} $attributes */
    public function handle(User $user, array $attributes): void
    {
        $oldAvatar = $user->avatar_path;
        $newAvatar = isset($attributes['avatar']) ? $attributes['avatar']->store('avatars', 'local') : null;
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
                Storage::disk('local')->delete($newAvatar);
            }
            throw $exception;
        }

        if ($newAvatar !== null && $oldAvatar !== null) {
            Storage::disk('local')->delete($oldAvatar);
        }
    }
}
