# OWASP CRS - Antispam Plugin

## Description

This is a plugin that brings protection against spam to CRS.

Plugin aims to detect spam comments coming to your web site. It scans predefined
GET/POST argument using [Rspamd](https://rspamd.com/) antispam software and, depending on the configuration,
sending results of the scan to your application using environment variables or fully
blocking the reuqest carring the spam data.

When predefined GET/POST argument is detected in the request, plugin sets the following
environment variables which can be accessed from your application:
 * `crs_antispam_plugin_spam_flag` with value of `1` if data were marked as spam, `0` otherwise
 * `crs_antispam_plugin_spam_score` with value of spam score (float) returned by Rspamd

As Rspamd spam tests are adjusted for e-mails, only `BAYES` symbols are used i.e. you
need to enable and configure Rspamd Statistical module for plugin to work.

## Prerequisities

 * ModSecurity compiled with Lua support
 * LuaSocket library
 * LuaJSON library
 * Working [Rspamd](https://rspamd.com/) instance with [Statistical module](https://rspamd.com/doc/configuration/statistic.html) enabled and configured

## LuaSocket library installation

LuaSocket library should be part of your linux distribution. Here is an example
of installation on Debian linux:  
`apt install lua-socket`

## LuaJSON library installation

LuaJSON library should be part of your linux distribution. Here is an example
of installation on Debian linux:  
`apt install lua-json`

## Plugin installation

For full and up to date instructions for the different available plugin
installation methods, refer to [How to Install a Plugin](https://coreruleset.org/docs/concepts/plugins/#how-to-install-a-plugin)
in the official CRS documentation.

## Configuration

All settings can be done in file `plugins/antispam-config.conf`.

### tx.antispam-plugin_scan_argument

GET or POST argument to scan for spam. There is no default value so you need to
set this depending on your application and needs.

### tx.antispam-plugin_spam_threshold

Enviromental variable `crs_antispam_plugin_spam_flag` will be set to `1` if spam
score of scanned data si bigger or equal to this setting. Additionaly, if
setting `tx.antispam-plugin_block_spam` is set to `1`, request is blocked.

This setting is used only if `tx.antispam-plugin_use_rspamd_threshold` setting
is set to `0`.

Default value: 5

### tx.antispam-plugin_block_spam

If set to `1`, request considered as spam will be blocked. Otherwise, only
enviromental variables are set.

Default value: 0

### tx.antispam-plugin_use_rspamd_threshold

If set to `1`, setting `tx.antispam-plugin_spam_threshold` is ignored and spam
threshold set in rspamd is used instead.

Default value: 0

### tx.antispam-plugin_rspamd_address

You need to set IP address or hostname of rspamd.

Default value: 127.0.0.1

### tx.antispam-plugin_rspamd_port

You need to set port or rspamd.

Default value: 11333

## Testing

First of all, don't forget to set `tx.antispam-plugin_scan_argument` setting (it
was set to `test` in the example below).

Set up a testing script which will print all environment variables, for example `print_env.php`:  
`<?php print_r($_ENV) ?>`

Now use a [GTUBE-like patterns](https://rspamd.com/doc/gtube_patterns.html) to access this script:  
`curl http://example.com/print_env.php --data 'test=XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X' | grep crs_`

If everything is ok, you should see this output:
```
    [crs_antispam_plugin_spam_flag] => 1
    [crs_antispam_plugin_spam_score] => 0
```

Note that `crs_antispam_plugin_spam_score` is `0`. This is because Rspamd is not
adding any spam score for it's GTUBE-like patterns.

## License

Copyright (c) 2023-2024 OWASP Core Rule Set project. All rights reserved.

The OWASP CRS and its official plugins are distributed
under Apache Software License (ASL) version 2. Please see the enclosed LICENSE
file for full details.
