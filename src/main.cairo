// Copyright 2023 StarkWare Industries Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License").
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.starkware.co/open-source-license/
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions
// and limitations under the License.

%builtins output
func main(output_ptr: felt*) -> (output_ptr: felt*) {
    alloc_locals;

    // Load fibonacci_claim_index and copy it to the output segment.
    local n;
    %{ ids.n = program_input["n"] %}

    local m;
    %{
        import requests
        resp = requests.post("https://cairo.test/sqrt", json={"n": ids.n}, verify=False)
        ids.m = resp.json()["n"]
    %}

    assert m * m = n;
    assert output_ptr[0] = m;

    // Return the updated output_ptr.
    return (output_ptr=&output_ptr[1]);
}
