#![no_main]
sp1_zkvm::entrypoint!(main);

use serde_json::Value; // Generic JSON.

fn main() {
    // Read generic JSON example input.
    let data_str = sp1_zkvm::io::read::<String>();
    let key = sp1_zkvm::io::read::<String>();

    // Process generic JSON.
    let v: Value = serde_json::from_str(&data_str).unwrap();
    let val = &v[key];
    println!("val: {}", val);

    // Parse the two values to be compared and the arithmetic operator.
    let num1 = v["num1"].as_i64().expect("Invalid num1");
    let num2 = v["num2"].as_i64().expect("Invalid num2");
    let operator = v["operator"].as_str().expect("Invalid operator");

    // Compare based on the arithmetic operator.
    let result = match operator {
        ">" => num1 > num2,
        ">=" => num1 >= num2,
        "<" => num1 < num2,
        "<=" => num1 <= num2,
        "==" => num1 == num2,
        _ => {
            println!("Unsupported operator: {}", operator);
            false // Unknown operator, default to false
        }
    };

    // Write the comparison result back to the output stream.
    sp1_zkvm::io::write(&result);

}