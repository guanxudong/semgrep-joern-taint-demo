#!/usr/bin/env perl
use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../lib";

use MyApp::Bus;
use MyApp::Config;
use MyApp::Handler::Executions;
use MyApp::Handler::Notifications;
use MyApp::Handler::Reconciliation;
use MyApp::Handler::Settlement;
use MyApp::Watcher;

MyApp::Bus::subscribe('execution.report', \&MyApp::Handler::Executions::on_execution_report);
MyApp::Bus::subscribe('execution.report_safe', \&MyApp::Handler::Executions::on_execution_report_safe);
MyApp::Bus::subscribe('reconcile.diff', \&MyApp::Handler::Reconciliation::on_diff_query);
MyApp::Bus::subscribe('reconcile.diff_safe', \&MyApp::Handler::Reconciliation::on_diff_query_safe);
MyApp::Bus::subscribe('reconcile.request', \&MyApp::Handler::Reconciliation::on_request);
MyApp::Bus::subscribe('reconcile.request_safe', \&MyApp::Handler::Reconciliation::on_request_safe);
MyApp::Bus::subscribe('alert.rule', \&MyApp::Handler::Reconciliation::on_alert_rule);
MyApp::Bus::subscribe('snapshot.load', \&MyApp::Handler::Reconciliation::on_load_snapshot);
MyApp::Bus::subscribe('ops.run_batch', \&MyApp::Handler::Reconciliation::on_run_batch);
MyApp::Bus::subscribe('reconcile.done', \&MyApp::Handler::Reconciliation::on_reconcile_done);
MyApp::Bus::subscribe('notify.send', \&MyApp::Handler::Notifications::on_notify);
MyApp::Watcher::watch(MyApp::Config::inbox_dir(), \&MyApp::Handler::Settlement::on_settlement_file);
MyApp::Watcher::watch(MyApp::Config::inbox_dir() . '_safe', \&MyApp::Handler::Settlement::on_settlement_file_safe);
MyApp::Watcher::scan_once();
