using System.Diagnostics;

namespace BadDemo.Services
{
    /// <summary>Diagnostic command logic; the target is stored in a field between calls.</summary>
    public class ToolService
    {
        /// <summary>Target staged by the controller between calls.</summary>
        private string _target = "";

        public void StageTarget(string host)
        {
            _target = host;
        }

        /// <summary>Runs the ping diagnostic against the staged target.</summary>
        public int RunStagedDiag()
        {
            var proc = Process.Start("cmd.exe", "/c ping " + _target);
            proc.WaitForExit();
            return proc.ExitCode;
        }
    }
}
