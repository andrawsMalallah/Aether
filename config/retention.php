<?php

return [
    // Enable only after reviewing a named environment's preview and recovery plan.
    'scheduled_enabled' => env('AETHER_RETENTION_ENABLED', false),
    'audit_days' => 365,
    'credential_days' => 30,
    'failed_job_days' => 30,
    'scan_limit' => 1000,
    'delete_limit' => 1000,
    'family_limit' => 20,
];
