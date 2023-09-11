%builtins output
func main(output_ptr: felt*) -> (output_ptr: felt*) {
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

    local m;
    %{
        import requests
        x = []
        for i in range(ids.domain_len):
            x.append(memory[ids.domain + i])
        resp = requests.post("https://proxy.test/request", json={"domain": x}, verify=False)
        ids.m = resp.json()["n"]
    %}

    assert output_ptr[0] = 0;

    // Return the updated output_ptr.
    return (output_ptr=&output_ptr[1]);
}
