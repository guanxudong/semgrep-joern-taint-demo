// Diagnostic command logic; taint stored in a field between calls.
const { exec } = require('child_process');

class ToolService {
  private target: string = '';

  stageTarget(host: string): void {
    this.target = host;
  }

  // Reads the staged field and reaches the shell sink (deep chain end).
  runStagedDiag(cb: (err: unknown, out: string) => void): void {
    exec('ping -c 1 ' + this.target, (err, stdout) => cb(err, stdout));
  }
}

export const toolService = new ToolService();
