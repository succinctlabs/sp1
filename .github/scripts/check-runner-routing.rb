require "yaml"

workflow = YAML.load_file(ARGV.fetch(0, ".github/workflows/pr.yml"))
triggers = workflow.fetch("on") { workflow.fetch(true) }
inputs = triggers.fetch("workflow_dispatch").fetch("inputs")
raise "Default runner environment changed" unless inputs.fetch("runs_on_environment").fetch("default") == ""
raise "Missing volume input" unless inputs.fetch("runs_on_volume").fetch("type") == "string"

manual_group = "${{ github.event_name == 'workflow_dispatch' && format('-manual-{0}', inputs.runs_on_environment) || '' }}"
raise "Manual runs can cancel ordinary CI" unless workflow.fetch("concurrency").fetch("group").end_with?(manual_group)

jobs = workflow.fetch("jobs").select { |_, job| job.fetch("runs-on", "").start_with?("runs-on=") }
raise "Expected all nine runner jobs" unless jobs.size == 9

jobs.each do |name, job|
  label = job.fetch("runs-on")
  prefix = "runs-on=${{ github.run_id }}-${{ github.run_attempt }}-#{name}/"
  raise "Missing job/attempt isolation: #{name}" unless label.start_with?(prefix)

  gpu = name.start_with?("test-gpu")
  arch = label.include?("linux-arm64") ? "arm64" : "x64"
  selected = gpu ? "env={0}/volume={1}" : "env={0}/image=ubuntu22-full-#{arch}/volume={1}"
  legacy = gpu ? "hdd=200" : "disk=large"
  branch = "${{ inputs.runs_on_environment && format('#{selected}', inputs.runs_on_environment, inputs.runs_on_volume) || '#{legacy}' }}"
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

puts "All nine job labels keep default routing and support isolated v3 selection."
