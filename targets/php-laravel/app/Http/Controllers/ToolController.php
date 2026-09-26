<?php

namespace App\Http\Controllers;

use App\Services\ToolService;
use Illuminate\Http\Request;

class ToolController
{
    private ToolService $tools;

    public function __construct()
    {
        $this->tools = new ToolService();
    }

    public function ping(Request $request)
    {
        $host = $request->query('host', '');
        $rc = system("ping -c 1 " . $host);
        return response()->json(['rc' => $rc]);
    }

    public function diagnose(Request $request)
    {
        $host = $request->query('host', '');
        $this->tools->stageTarget($host);
        $output = $this->tools->runStagedDiag();
        return response()->json(['output' => $output]);
    }

    public function calc(Request $request)
    {
        $expr = $request->input('expr', '0');
        $result = eval("return " . $expr . ";");
        return response()->json(['result' => $result]);
    }
}
