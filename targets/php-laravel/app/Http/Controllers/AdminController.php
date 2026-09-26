<?php

namespace App\Http\Controllers;

use App\Repositories\Db;

class AdminController
{
    public function listUsers()
    {
        $rows = Db::query("SELECT id, username, email, role FROM users");
        return response()->json($rows);
    }

    public function destroy(int $id)
    {
        Db::execute("DELETE FROM users WHERE id = " . $id);
        return response()->json(['deleted' => $id]);
    }
}
