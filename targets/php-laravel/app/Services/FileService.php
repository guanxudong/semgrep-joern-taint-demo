<?php

namespace App\Services;

class FileService
{
    private const ALLOWED_FILES = ['readme.txt', 'help.txt'];

    private string $uploadDir;

    public function __construct()
    {
        $config = require __DIR__ . '/../../config/app.php';
        $this->uploadDir = $config['upload_dir'];
    }

    public function readUserFile(string $name): string
    {
        $path = $this->uploadDir . '/' . $name;
        return file_get_contents($path);
    }

    public function readWhitelisted(string $name): string
    {
        if (!in_array($name, self::ALLOWED_FILES, true)) {
            throw new \InvalidArgumentException('file not allowed');
        }
        $path = $this->uploadDir . '/' . $name;
        return file_get_contents($path);
    }
}
