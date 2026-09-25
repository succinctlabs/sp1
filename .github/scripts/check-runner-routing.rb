require "yaml"

DEFAULT_VOLUME = "150gb:gp3:750mbps:4000iops"

def select_runner(event, configured, manual, manual_volume)
  environment = event == "workflow_dispatch" ? manual : configured
  volume = event == "workflow_dispatch" ? manual_volume : DEFAULT_VOLUME
  raise "Invalid runner environment" unless environment.empty? || environment.match?(/\A[A-Za-z0-9][A-Za-z0-9_-]*\z/)
  if !environment.empty? && !volume.match?(/\A[1-9][0-9]*gb:gp3:[1-9][0-9]*mbps:[1-9][0-9]*iops\z/)
    raise "Invalid runner volume"
  end
  { "environment" => environment, "volume" => environment.empty? ? "" : volume }
end

# Exercise both routes before exporting the selection to downstream jobs.
%w[pull_request push merge_group].each do |event|
  raise "Default route changed" unless select_runner(event, "", "manual", "invalid")["environment"] == ""
  raise "Configured route ignored" unless select_runner(event, "test-v3", "manual", "invalid") == {
    "environment" => "test-v3", "volume" => DEFAULT_VOLUME
  }
end
raise "Manual empty selection changed" unless select_runner("workflow_dispatch", "test-v3", "", "")["environment"] == ""
raise "Manual selection ignored" unless select_runner("workflow_dispatch", "ignored", "manual", "200gb:gp3:750mbps:4000iops") == {
  "environment" => "manual", "volume" => "200gb:gp3:750mbps:4000iops"
}
[["push", "bad/env", "", ""], ["push", "bad\nvalue", "", ""],
 ["workflow_dispatch", "", "manual", "bad/volume"]].each do |args|
  begin
    select_runner(*args)
  rescue RuntimeError
    next
  end
  raise "Invalid selection accepted"
end

workflow = YAML.load_file(ARGV.fetch(0, ".github/workflows/pr.yml"))
triggers = workflow.fetch("on") { workflow.fetch(true) }
inputs = triggers.fetch("workflow_dispatch").fetch("inputs")
raise "Default runner environment changed" unless inputs.fetch("runs_on_environment").fetch("default") == ""
raise "Missing volume input" unless inputs.fetch("runs_on_volume").fetch("type") == "string"

manual_group = "${{ github.event_name == 'workflow_dispatch' && format('-manual-{0}', inputs.runs_on_environment) || '' }}"
raise "Manual runs can cancel ordinary CI" unless workflow.fetch("concurrency").fetch("group").end_with?(manual_group)

jobs = workflow.fetch("jobs").select { |_, job| job.fetch("runs-on", "").start_with?("runs-on=") }
raise "Expected all nine runner jobs" unless jobs.size == 9

routing = workflow.fetch("jobs").fetch("runner-routing")
raise "Routing check needs a hosted runner" unless routing.fetch("runs-on") == "ubuntu-latest"
%w[environment volume].each do |key|
  raise "Missing routing output: #{key}" unless routing.fetch("outputs").fetch(key) == "${{ steps.routing.outputs.#{key} }}"
end
step = routing.fetch("steps").find { |s| s["id"] == "routing" }
raise "Missing routing command" unless step.fetch("run") == "ruby .github/scripts/check-runner-routing.rb"
raise "Incorrect routing inputs" unless step.fetch("env") == {
  "SP1_CI_RUNS_ON_ENVIRONMENT" => "${{ vars.SP1_CI_RUNS_ON_ENVIRONMENT }}",
  "MANUAL_RUNS_ON_ENVIRONMENT" => "${{ inputs.runs_on_environment }}",
  "MANUAL_RUNS_ON_VOLUME" => "${{ inputs.runs_on_volume }}"
}

jobs.each do |name, job|
  raise "Job can skip routing validation: #{name}" unless job.fetch("needs") == "runner-routing" && !job.key?("if")
  label = job.fetch("runs-on")
  prefix = "runs-on=${{ github.run_id }}-${{ github.run_attempt }}-#{name}/"
  raise "Missing job/attempt isolation: #{name}" unless label.start_with?(prefix)

  gpu = name.start_with?("test-gpu")
  arch = label.include?("linux-arm64") ? "arm64" : "x64"
  selected = gpu ? "env={0}/volume={1}" : "env={0}/image=ubuntu22-full-#{arch}/volume={1}"
  legacy = gpu ? "hdd=200" : "disk=large"
  branch = "${{ needs.runner-routing.outputs.environment && format('#{selected}', needs.runner-routing.outputs.environment, needs.runner-routing.outputs.volume) || '#{legacy}' }}"
  raise "Incorrect environment selection: #{name}" unless label.scan(branch).size == 1

  default_label = label.sub(branch, legacy)
  selected_label = label.sub(branch, selected.sub("{0}", "test-v3").sub("{1}", "200gb:gp3:750mbps:4000iops"))
  raise "Default routing changed: #{name}" if default_label.include?("/env=") || default_label.include?("/volume=")
  raise "Legacy storage used on v3: #{name}" if selected_label.match?(%r{/(disk|hdd)=})
  raise "On-demand selection changed: #{name}" unless default_label.include?("/spot=false")
  if gpu
    raise "GPU type changed: #{name}" unless label.include?("/family=g6.4xlarge/")
    raise "GPU image changed: #{name}" unless label.include?("/ami=ami-0a63dc9cb9e934ba3/")
  end
end

selection = select_runner(ENV.fetch("GITHUB_EVENT_NAME", ""), ENV.fetch("SP1_CI_RUNS_ON_ENVIRONMENT", ""),
                          ENV.fetch("MANUAL_RUNS_ON_ENVIRONMENT", ""), ENV.fetch("MANUAL_RUNS_ON_VOLUME", ""))
if ENV["GITHUB_OUTPUT"]
  File.open(ENV.fetch("GITHUB_OUTPUT"), "a") { |file| selection.each { |key, value| file.puts "#{key}=#{value}" } }
end
puts "All nine job labels passed default, configured, and manual routing checks."
