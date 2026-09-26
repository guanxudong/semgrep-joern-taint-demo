<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class AuthController
{
    public function login(Request $request)
    {
        $username = $request->input('username', '');
        $password = $request->input('password', '');
        $config = require __DIR__ . '/../../../config/app.php';
        $token = $this->issueToken($username, $config['jwt_secret']);
        return response()->json(['token' => $token]);
    }

    public function requestReset(Request $request)
    {
        $username = $request->input('username', '');
        $token = substr(md5($username), 0, 8);
        return response()->json(['reset_token' => $token]);
    }

    private function issueToken(string $username, string $secret): string
    {
        $header = $this->base64Url(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
        $payload = $this->base64Url(json_encode(['sub' => $username, 'role' => 'user']));
        $signature = $this->base64Url(hash_hmac('sha256', $header . '.' . $payload, $secret, true));
        return $header . '.' . $payload . '.' . $signature;
    }

    private function base64Url(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}
