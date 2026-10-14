<?php

namespace App\Http\Controllers\OAuth;

use App\Http\Controllers\Controller;
use App\Http\Resources\OidcResource;
use App\Services\OAuth\OidcKeys;
use App\Services\OAuth\OidcMetadata;

class OidcMetadataController extends Controller
{
    public function discovery(OidcMetadata $metadata): OidcResource
    {
        return new OidcResource($metadata->discovery());
    }

    public function keys(OidcKeys $keys): OidcResource
    {
        return new OidcResource(['keys' => [$keys->jwk()]]);
    }
}
