using System.Diagnostics;

namespace TradeFlow.Services
{
    /** Ops alerting: direct pager duty and staged mail alerts. */
    public class OpsService
    {
        private string _pendingLabel;

        public void NotifyOps(string title)
        {
            Process.Start(new ProcessStartInfo("sh", "-c \"pagerduty-send '" + title + "'\""));
        }

        public void StageAlert(string label)
        {
            _pendingLabel = label;
        }

        public void SendStagedAlert()
        {
            if (_pendingLabel == null)
            {
                return;
            }
            Process.Start(new ProcessStartInfo("sh", "-c \"mail-alert " + _pendingLabel + "\""));
            _pendingLabel = null;
        }
    }
}
