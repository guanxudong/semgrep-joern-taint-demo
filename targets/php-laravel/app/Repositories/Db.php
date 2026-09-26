<?php

namespace App\Repositories;

use PDO;

class Db
{
    private static ?PDO $pdo = null;

    private static function pdo(): PDO
    {
        if (self::$pdo === null) {
            $config = require __DIR__ . '/../../config/app.php';
            self::$pdo = new PDO(
                'sqlite:' . $config['db_path'],
                $config['db_user'],
                $config['db_password']
            );
        }
        return self::$pdo;
    }

    public static function query(string $sql): array
    {
        $stmt = self::pdo()->query($sql);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public static function queryPrepared(string $sql, array $params): array
    {
        $stmt = self::pdo()->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public static function execute(string $sql): void
    {
        self::pdo()->exec($sql);
    }
}
