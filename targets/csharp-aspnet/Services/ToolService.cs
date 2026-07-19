using System.Diagnostics;

namespace BadDemo.Services
{
    /// <summary>Diagnostic command logic; taint stored in a field between calls.</summary>
    public class ToolService
    {
        /// <summary>Tainted value staged by the controller (taint via field).</summary>
        private string _target = "";

        public void StageTarget(string host)
        {
            _target = host;
        }

        /// <summary>Reads the staged field and reaches the shell sink (deep chain end).</summary>
        public int RunStagedDiag()
        {
            var proc = Process.Start("cmd.exe", "/c ping " + _target);
            proc.WaitForExit();
            return proc.ExitCode;
        }
    }
}
