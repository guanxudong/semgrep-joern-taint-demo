<?php

namespace App\Services;

use App\Repositories\Db;

class UserService
{
    private string $pendingName = '';

    public function stageName(string $name): void
    {
        $this->pendingName = $name;
    }

    public function findStaged(): array
    {
        $sql = "SELECT id, username, email FROM users WHERE username = '" . $this->pendingName . "'";
        return Db::query($sql);
    }

    public function findById(int $id): array
    {
        $sql = "SELECT id, username, email, role FROM users WHERE id = " . $id;
        return Db::query($sql);
    }

    public function findByIdPrepared(int $id): array
    {
        return Db::queryPrepared("SELECT id, username, email, role FROM users WHERE id = ?", [$id]);
    }
}
