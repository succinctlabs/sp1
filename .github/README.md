# PR workflow runners

The `PR` workflow uses its existing runners when the repository variable `SP1_CI_RUNS_ON_ENVIRONMENT` is empty.
To select another RunsOn environment for ordinary PR, push, and merge-group jobs, set this variable to its environment name.
Prepare that environment before you set the variable.
The selected environment uses a `150gb:gp3:750mbps:4000iops` root volume.
GPU jobs keep their instance type and AMI.

The GitHub-hosted `Runner routing` job validates the selection before the nine RunsOn jobs can start.
An invalid environment name or volume fails that check.
The variable affects only this workflow.

Manual runs use their `runs_on_environment` and `runs_on_volume` inputs independently of the repository variable.
An empty manual environment input selects the existing runners.

Clear `SP1_CI_RUNS_ON_ENVIRONMENT` to restore the existing route for new ordinary runs.
This does not move jobs that already have runner labels or stop their instances.

Run `ruby .github/scripts/check-runner-routing.rb` to check both routes and the manual selection locally.
