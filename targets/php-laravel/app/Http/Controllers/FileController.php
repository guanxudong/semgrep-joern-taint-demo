<?php

namespace App\Http\Controllers;

use App\Services\FileService;
use Illuminate\Http\Request;

class FileController
{
    private FileService $files;

    public function __construct()
    {
        $this->files = new FileService();
    }

    public function download(Request $request)
    {
        $name = $request->query('name', '');
        $content = $this->files->readUserFile($name);
        return response()->json(['content' => $content]);
    }

    public function downloadV2(Request $request)
    {
        $name = $request->query('name', '');
        try {
            $content = $this->files->readWhitelisted($name);
        } catch (\InvalidArgumentException $e) {
            return response()->json(['error' => 'file not allowed'], 400);
        }
        return response()->json(['content' => $content]);
    }
}
