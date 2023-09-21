%builtins output
func main{output_ptr: felt*}() {
    alloc_locals;

    // Load fibonacci_claim_index and copy it to the output segment.
    local domain: felt*;
    local domain_len;
    %{
        x = program_input["domain"]
        ids.domain = domain = segments.add()
        for i, val in enumerate(x):
            memory[domain + i] = val
        ids.domain_len = len(x)
    %}

    local status;
    local secrets: felt*;
    local secrets_len: felt;
    %{
        import requests
        x = []
        for i in range(ids.domain_len):
            x.append(memory[ids.domain + i])
        resp = requests.post("https://proxy.test/request", json={"domain": x}, verify=False)
        ids.status = resp.json()["status_code"]
        response = resp.json()

        resp_secrets = response["connection_secrets"]
        ids.secrets = secrets = segments.add()
        for i, val in enumerate(resp_secrets):
            memory[secrets + i] = val
        ids.secrets_len = len(resp_secrets)
    %}

    assert output_ptr[0] = status;
    assert output_ptr[1] = secrets_len;
    let output_ptr = output_ptr + 2;
    print_output(secrets_len, secrets);

    // Return the updated output_ptr.
    return ();
}

func print_output{output_ptr: felt*}(data_len: felt, data: felt*) {
    if (data_len == 0) {
        return ();
    }
    assert output_ptr[0] = data[0];
    let output_ptr = output_ptr + 1;
    print_output(data_len - 1, data + 1);
    return ();
}
