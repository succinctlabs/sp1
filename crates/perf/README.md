# SP1 Testing Suite

## Prerequisites

- [GitHub CLI](https://cli.github.com/)

## Run the testing suite

Set the flags to run on the set of workloads you want to test on.

```
gh workflow run "Testing Suite" --ref <MY_BRANCH> -f cpu=true -f cuda=true -f network=true
```