<?php

namespace Qihucms\PassportAuth;

use GuzzleHttp\Client;

class TokenProxy
{
    public function proxy($grantType, $data = [])
    {
        $data = array_merge(
            $data,
            [
                'grant_type' => $grantType,
                'client_id' => env('PASSPORT_CLIENT_ID'),
                'client_secret' => env('PASSPORT_CLIENT_SECRET')
            ]
        );

        $http = new Client(['timeout' => 2.0, 'verify' => false]);

        $response = $http->post(
            route('passport.token'),
            ['form_params' => $data]
        );

        $token = json_decode((string)$response->getBody(), true);

        return response()->json(
            [
                'token' => $token['access_token'],
                'expires_in' => $token['expires_in'],
                'refresh_token' => $token['refresh_token'],
                'refresh_token_expires_in' => 2592000,
            ]
        );
    }
}