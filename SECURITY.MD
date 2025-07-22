# SP1 Security Policy

## Overview

This document explains Succinct's process for handling reported issues and what to expect.

## Audits

You can find audits of SP1 [here](https://github.com/succinctlabs/sp1/tree/dev/audits).

## Security Advisory Monitoring

Security advisories for SP1 can be found [here](https://github.com/succinctlabs/sp1/security).

## Reporting a Security Bug

All security bugs in SP1's production distribution should be reported through the SP1 Bug Bounty program on Code4rena [here](https://code4rena.com/bounties/succinct). 

If you need to contact the SP1 team by email regarding security, please use the address `security@succinct.xyz`.

## Tracks

Depending on the nature of your issue, it will be categorized as an issue in the **PUBLIC**, **PRIVATE**, or **URGENT** track.

### PUBLIC

Issues in the **PUBLIC** track affect niche configurations, have very limited impact, or are already widely known.

**PUBLIC** track issues are fixed on the dev branch and backported to the next scheduled minor releases.

### PRIVATE

Issues in the **PRIVATE** track are violations of committed security properties.

**PRIVATE** track issues are fixed in the next scheduled minor releases and are kept private until then.

Days before the release, a pre-announcement is sent to partners, indicating the presence of a security fix in the upcoming releases and which component in SP1 is affected (without disclosing detailed information).

### URGENT

**URGENT** track issues are a threat to SP1's ecosystem integrity or are actively exploited in the wild causing severe damage.

**URGENT** track issues are fixed in private and trigger an immediate dedicated security release, possibly with no pre-announcement.

## Disclosure Process

The SP1 project uses the following disclosure process:

* Once the security report is received, it is assigned a primary handler. This person coordinates the fix and release process.
* The issue is confirmed and a list of affected components is determined.
* Code is audited to find any potential similar problems.
* Fixes are prepared for the next major and minor releases.
* On the date the fixes are applied, issues are disclosed as security advisories on the repository and partners are notified.

This process can take some time, especially when coordination with other maintainers is needed. Every effort will be made to handle the bug as quickly as possible, but it's important to follow this process to ensure that disclosures are handled consistently.

Vulnerabilities should be kept private until the Succinct team explicitly communicates otherwise.

## Acknowledgements

This document is based on the [Gnark Security Policy](https://github.com/Consensys/gnark/blob/master/SECURITY.md).
