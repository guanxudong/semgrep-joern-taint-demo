<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Blade;

class RenderController
{
    public function hello(Request $request)
    {
        $name = $request->query('name', '');
        return "<h1>Hello " . $name . "</h1>";
    }

    public function preview(Request $request)
    {
        $tpl = $request->query('tpl', '');
        return Blade::render($tpl);
    }
}
