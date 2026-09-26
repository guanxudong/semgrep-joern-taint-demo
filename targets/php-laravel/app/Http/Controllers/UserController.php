<?php

namespace App\Http\Controllers;

use App\Repositories\Db;
use App\Services\UserService;
use Illuminate\Http\Request;

class UserController
{
    private UserService $users;

    public function __construct()
    {
        $this->users = new UserService();
    }

    public function search(Request $request)
    {
        $q = $request->query('q', '');
        $rows = Db::query("SELECT id, username FROM users WHERE username LIKE '%" . $q . "%'");
        return response()->json($rows);
    }

    public function lookup(Request $request)
    {
        $name = $request->query('name', '');
        $this->users->stageName($name);
        $rows = $this->users->findStaged();
        return response()->json($rows);
    }

    public function show(int $id)
    {
        $rows = $this->users->findById($id);
        return response()->json($rows);
    }

    public function searchV2(Request $request)
    {
        $q = $request->query('q', '');
        $rows = Db::queryPrepared("SELECT id, username FROM users WHERE username LIKE ?", ['%' . $q . '%']);
        return response()->json($rows);
    }

    public function me(Request $request, int $id)
    {
        $callerId = (int) $request->header('X-User-Id', '-1');
        if ($callerId !== $id) {
            return response()->json(['error' => 'forbidden'], 403);
        }
        $rows = $this->users->findByIdPrepared($id);
        return response()->json($rows);
    }
}
