use crate::worker::RawTaskRequest;

pub struct ExecuteSlicingTask;

impl ExecuteSlicingTask {
    pub async fn run(request: RawTaskRequest) {
        let RawTaskRequest { inputs, outputs, context } = request;
        let [elf, stdin, mode, cycle_limit] = inputs.try_into().unwrap();
        let [output] = outputs.try_into().unwrap();

        let _ = (context, elf, stdin, mode, cycle_limit, output);
    }
}
