<?php

namespace App\Services;

class ToolService
{
    private string $target = '';

    public function stageTarget(string $host): void
    {
        $this->target = $host;
    }

    public function runStagedDiag(): ?string
    {
        $cmd = "ping -c 1 " . $this->target;
        return shell_exec($cmd);
    }
}
