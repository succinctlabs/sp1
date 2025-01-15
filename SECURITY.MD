# SP1 Security Policy

## Overview

This document explains the Succinct's process for handling issues reported and what to expect in return.

## Audits

You can find audits of SP1 [here](https://github.com/succinctlabs/sp1/tree/dev/audits).

## Security Advisory Monitoring

Security advisories for SP1 can be found [here](https://github.com/succinctlabs/sp1/security).

## Reporting a Security Bug

All security bugs in SP1's production distribution should be reported by email to security@succinct.xyz. Only bugs in last two major releases will be accepted.

Your email will be acknowledged within 7 days, and you'll be kept up to date with the progress until resolution. Your issue will be fixed or made public.

If you have not received a reply to your email within 7 days, please follow up with the Succinct team again at security@succinct.xyz. 

Note that we do not currently run any bug bounty program.

## Tracks

Depending on the nature of your issue, it will be categorized as an issue in the **PUBLIC**, **PRIVATE**, or **URGENT** track.

### PUBLIC

Issues in the **PUBLIC** track affect niche configurations, have very limited impact, or are already widely known.

**PUBLIC** track issues are fixed on the dev branch, and get backported to the next scheduled minor releases.

### PRIVATE

Issues in the **PRIVATE** track are violations of committed security properties.

**PRIVATE** track issues are fixed in the next scheduled minor releases, and are kept private until then.

Days before the release, a pre-announcement is sent to partners, announcing the presence of a security fix in the upcoming releases, and which component in SP1 is affected (but not disclosing any more details).

### URGENT

**URGENT** track issues are a threat to the SP1 ecosystem's integrity, or are being actively exploited in the wild leading to severe damage.

**URGENT** track issues are fixed in private, and trigger an immediate dedicated security release, possibly with no pre-announcement.

## Disclosure Process

The SP1 project uses the following disclosure process:

* Once the security report is received it is assigned a primary handler. This person coordinates the fix and release process.
* The issue is confirmed and a list of affected components is determined.
* Code is audited to find any potential similar problems.
* Fixes are prepared for the next major and minor releases.
* On the date that the fixes are applied, issues are disclosed as security advisories on the repository and partners are notified.

This process can take some time, especially when coordination is required with maintainers of other projects. Every effort will be made to handle the bug in as timely a manner as possible, however it's important that we follow the process described above to ensure that disclosures are handled consistently.

Vulnerabilities should be kept private until otherwise communicated by the Succinct team. This policy is to ensure a fix can be made in private and not be actively exploited.

## Acknowledgements

This document is based on the [Gnark Security Policy](https://github.com/Consensys/gnark/blob/master/SECURITY.md).