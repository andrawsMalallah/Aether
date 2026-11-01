<?php

// S3Mock has a bundled self-signed certificate. This overlay is mounted only
// in isolated test containers; it never enters the production image/config.
$configuration = require '/container-fixtures/filesystems-base.php';
$configuration['disks']['private_s3']['http']['verify'] = false;

return $configuration;
