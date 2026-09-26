<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class ProfileUser
{
    public string $username = '';
    public string $email = '';
    public string $role = 'user';
}

class ProfileController
{
    private static array $users = [];

    private function userStore(string $username): ProfileUser
    {
        if (!isset(self::$users[$username])) {
            self::$users[$username] = new ProfileUser();
        }
        return self::$users[$username];
    }

    public function update(Request $request)
    {
        $username = $request->input('username', '');
        $user = $this->userStore($username);
        foreach ($request->all() as $key => $value) {
            $user->$key = $value;
        }
        return response()->json([
            'username' => $user->username,
            'email' => $user->email,
            'role' => $user->role,
        ]);
    }

    public function import(Request $request)
    {
        $data = $request->getContent();
        $user = unserialize($data);
        self::$users[$user->username] = $user;
        return response()->json(['imported' => $user->username]);
    }
}
